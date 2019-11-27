#!/usr/bin/env bash

set -o pipefail
set -o nounset
set -o errexit
IFS=$'\n\t'

TEMPLATE_DIR=${TEMPLATE_DIR:-/tmp/worker}

################################################################################
### Validate Required Arguments ################################################
################################################################################
validate_env_set() {
    (
        set +o nounset

        if [ -z "${!1}" ]; then
            echo "Packer variable '$1' was not set. Aborting"
            exit 1
        fi
    )
}

validate_env_set BINARY_BUCKET_NAME
validate_env_set BINARY_BUCKET_REGION
validate_env_set DOCKER_VERSION
validate_env_set CNI_VERSION
validate_env_set CNI_PLUGIN_VERSION
validate_env_set KUBERNETES_VERSION
validate_env_set KUBERNETES_BUILD_DATE

################################################################################
### Machine Architecture #######################################################
################################################################################

MACHINE=$(uname -m)
if [ "$MACHINE" == "x86_64" ]; then
    ARCH="amd64"
elif [ "$MACHINE" == "aarch64" ]; then
    ARCH="arm64"
else
    echo "Unknown machine architecture '$MACHINE'" >&2
    exit 1
fi

################################################################################
### Packages ###################################################################
################################################################################

# patch in kernel 4.19
# see: https://github.com/awslabs/amazon-eks-ami/issues/357
sudo amazon-linux-extras install -y kernel-ng

# Update the OS to begin with to catch up to the latest packages.
sudo yum update -y

# Install necessary packages
sudo yum install -y \
    aws-cfn-bootstrap \
    awscli \
    chrony \
    conntrack \
    curl \
    jq \
    ec2-instance-connect \
    nfs-utils \
    socat \
    unzip \
    wget

# Remove the ec2-net-utils package, if it's installed. This package interferes with the route setup on the instance.
if yum list installed | grep ec2-net-utils; then sudo yum remove ec2-net-utils -y -q; fi

################################################################################
### Time #######################################################################
################################################################################

# Make sure Amazon Time Sync Service starts on boot.
sudo chkconfig chronyd on

# Make sure that chronyd syncs RTC clock to the kernel.
cat <<EOF | sudo tee -a /etc/chrony.conf
# This directive enables kernel synchronisation (every 11 minutes) of the
# real-time clock. Note that it can’t be used along with the 'rtcfile' directive.
rtcsync
EOF

# If current clocksource is xen, switch to tsc
if grep --quiet xen /sys/devices/system/clocksource/clocksource0/current_clocksource &&
  grep --quiet tsc /sys/devices/system/clocksource/clocksource0/available_clocksource; then
    echo "tsc" | sudo tee /sys/devices/system/clocksource/clocksource0/current_clocksource
else
    echo "tsc as a clock source is not applicable, skipping."
fi

################################################################################
### iptables ###################################################################
################################################################################

# Enable forwarding via iptables
sudo bash -c "/sbin/iptables-save > /etc/sysconfig/iptables"

sudo mv $TEMPLATE_DIR/iptables-restore.service /etc/systemd/system/iptables-restore.service

sudo systemctl daemon-reload
sudo systemctl enable iptables-restore

################################################################################
### Docker #####################################################################
################################################################################

sudo yum install -y yum-utils device-mapper-persistent-data lvm2

INSTALL_DOCKER="${INSTALL_DOCKER:-true}"
if [[ "$INSTALL_DOCKER" == "true" ]]; then
    sudo amazon-linux-extras enable docker
    sudo yum install -y docker-${DOCKER_VERSION}*
    sudo usermod -aG docker $USER

    # Remove all options from sysconfig docker.
    sudo sed -i '/OPTIONS/d' /etc/sysconfig/docker

    sudo mkdir -p /etc/docker
    sudo mv $TEMPLATE_DIR/docker-daemon.json /etc/docker/daemon.json
    sudo chown root:root /etc/docker/daemon.json

    # Enable docker daemon to start on boot.
    sudo systemctl daemon-reload
    sudo systemctl enable docker

    # have larger logfiles to allow fluentd or others to pick them up
    # this is a race condition between a (log) bursting container and the
    # interval fluentd lists new files in /var/log/containers (default: 60s)
    # we merge in the value to be transparent on any new settings AWS is placing in /etc/docker/daemon.json
    tmp=$(mktemp) && sudo jq '."log-opts"."max-size" = "250m" | ."log-opts"."max-file" = "3"' /etc/docker/daemon.json > ${tmp} && sudo mv -f ${tmp} /etc/docker/daemon.json
fi

################################################################################
### Logrotate ##################################################################
################################################################################

# kubelet uses journald which has built-in rotation and capped size.
# See man 5 journald.conf
sudo mv $TEMPLATE_DIR/logrotate-kube-proxy /etc/logrotate.d/kube-proxy
sudo chown root:root /etc/logrotate.d/kube-proxy
sudo mkdir -p /var/log/journal

################################################################################
### Kubernetes #################################################################
################################################################################

sudo mkdir -p /etc/kubernetes/manifests
sudo mkdir -p /var/lib/kubernetes
sudo mkdir -p /var/lib/kubelet
sudo mkdir -p /opt/cni/bin

wget https://github.com/containernetworking/cni/releases/download/${CNI_VERSION}/cni-${ARCH}-${CNI_VERSION}.tgz
wget https://github.com/containernetworking/cni/releases/download/${CNI_VERSION}/cni-${ARCH}-${CNI_VERSION}.tgz.sha512
sudo sha512sum -c cni-${ARCH}-${CNI_VERSION}.tgz.sha512
sudo tar -xvf cni-${ARCH}-${CNI_VERSION}.tgz -C /opt/cni/bin
rm cni-${ARCH}-${CNI_VERSION}.tgz cni-${ARCH}-${CNI_VERSION}.tgz.sha512

wget https://github.com/containernetworking/plugins/releases/download/${CNI_PLUGIN_VERSION}/cni-plugins-${ARCH}-${CNI_PLUGIN_VERSION}.tgz
wget https://github.com/containernetworking/plugins/releases/download/${CNI_PLUGIN_VERSION}/cni-plugins-${ARCH}-${CNI_PLUGIN_VERSION}.tgz.sha512
sudo sha512sum -c cni-plugins-${ARCH}-${CNI_PLUGIN_VERSION}.tgz.sha512
sudo tar -xvf cni-plugins-${ARCH}-${CNI_PLUGIN_VERSION}.tgz -C /opt/cni/bin
rm cni-plugins-${ARCH}-${CNI_PLUGIN_VERSION}.tgz cni-plugins-${ARCH}-${CNI_PLUGIN_VERSION}.tgz.sha512

echo "Downloading binaries from: s3://$BINARY_BUCKET_NAME"
S3_DOMAIN="s3-$BINARY_BUCKET_REGION"
if [ "$BINARY_BUCKET_REGION" = "us-east-1" ]; then
    S3_DOMAIN="s3"
fi
S3_URL_BASE="https://$BINARY_BUCKET_NAME.$S3_DOMAIN.amazonaws.com/$KUBERNETES_VERSION/$KUBERNETES_BUILD_DATE/bin/linux/$ARCH"
S3_PATH="s3://$BINARY_BUCKET_NAME/$KUBERNETES_VERSION/$KUBERNETES_BUILD_DATE/bin/linux/$ARCH"

BINARIES=(
    kubelet
    aws-iam-authenticator
)
for binary in ${BINARIES[*]} ; do
    if [[ ! -z "$AWS_ACCESS_KEY_ID" ]]; then
        echo "AWS cli present - using it to copy binaries from s3."
        aws s3 cp --region $BINARY_BUCKET_REGION $S3_PATH/$binary .
        aws s3 cp --region $BINARY_BUCKET_REGION $S3_PATH/$binary.sha256 .
    else
        echo "AWS cli missing - using wget to fetch binaries from s3. Note: This won't work for private bucket."
        sudo wget $S3_URL_BASE/$binary
        sudo wget $S3_URL_BASE/$binary.sha256
    fi
    sudo sha256sum -c $binary.sha256
    sudo chmod +x $binary
    sudo mv $binary /usr/bin/
done
sudo rm *.sha256

KUBERNETES_MINOR_VERSION=${KUBERNETES_VERSION%.*}

sudo mkdir -p /etc/kubernetes/kubelet
sudo mkdir -p /etc/systemd/system/kubelet.service.d
sudo mv $TEMPLATE_DIR/kubelet-kubeconfig /var/lib/kubelet/kubeconfig
sudo chown root:root /var/lib/kubelet/kubeconfig
if [ "$KUBERNETES_MINOR_VERSION" = "1.14" ]; then
    sudo mv $TEMPLATE_DIR/1.14/kubelet.service /etc/systemd/system/kubelet.service
else
    sudo mv $TEMPLATE_DIR/kubelet.service /etc/systemd/system/kubelet.service
fi
sudo chown root:root /etc/systemd/system/kubelet.service
sudo mv $TEMPLATE_DIR/kubelet-config.json /etc/kubernetes/kubelet/kubelet-config.json
sudo chown root:root /etc/kubernetes/kubelet/kubelet-config.json


sudo systemctl daemon-reload
# Disable the kubelet until the proper dropins have been configured
sudo systemctl disable kubelet

################################################################################
### EKS ########################################################################
################################################################################

sudo mkdir -p /etc/eks
sudo mv $TEMPLATE_DIR/eni-max-pods.txt /etc/eks/eni-max-pods.txt
sudo mv $TEMPLATE_DIR/bootstrap.sh /etc/eks/bootstrap.sh
sudo chmod +x /etc/eks/bootstrap.sh

################################################################################
### AMI Metadata ###############################################################
################################################################################

BASE_AMI_ID=$(curl -s  http://169.254.169.254/latest/meta-data/ami-id)
cat <<EOF > /tmp/release
BASE_AMI_ID="$BASE_AMI_ID"
BUILD_TIME="$(date)"
BUILD_KERNEL="$(uname -r)"
ARCH="$(uname -m)"
EOF
sudo mv /tmp/release /etc/eks/release
sudo chown root:root /etc/eks/*

################################################################################
### Stuff required by "protectKernelDefaults=true" #############################
################################################################################

cat <<EOF | sudo tee -a /etc/sysctl.d/99-amazon.conf
vm.overcommit_memory=1
kernel.panic=10
kernel.panic_on_oops=1
EOF

################################################################################
### AWS SSM Agent ##############################################################
################################################################################

INSTALL_SSM_AGENT="${INSTALL_SSM_AGENT:-true}"
SSM_AGENT_CW_LOG="${SSM_AGENT_CW_LOG:-false}"
SSM_AGENT_CW_LOGGROUP="${SSM_AGENT_CW_LOGGROUP:-/ssm/agents}"
if [[ "$INSTALL_SSM_AGENT" == "true" ]]; then
    sudo yum install -y amazon-ssm-agent

    if [[ "$SSM_AGENT_CW_LOG" == "true" ]]; then
        # see: https://docs.aws.amazon.com/systems-manager/latest/userguide/monitoring-ssm-agent.html
        cat <<EOT | sudo tee /etc/amazon/ssm/seelog.xml
        <seelog type="adaptive" mininterval="2000000" maxinterval="100000000" critmsgcount="500" minlevel="info">
            <exceptions>
                <exception filepattern="test*" minlevel="error"/>
            </exceptions>
            <outputs formatid="fmtinfo">
                <console formatid="fmtinfo"/>
                <rollingfile type="size" filename="/var/log/amazon/ssm/amazon-ssm-agent.log" maxsize="30000000" maxrolls="5"/>
                <filter levels="error,critical" formatid="fmterror">
                    <rollingfile type="size" filename="/var/log/amazon/ssm/errors.log" maxsize="10000000" maxrolls="5"/>
                </filter>
                <custom name="cloudwatch_receiver" formatid="fmtdebug" data-log-group="$SSM_AGENT_CW_LOGGROUP"/>
            </outputs>
            <formats>
                <format id="fmterror" format="%Date %Time %LEVEL [%FuncShort @ %File.%Line] %Msg%n"/>
                <format id="fmtdebug" format="%Date %Time %LEVEL [%FuncShort @ %File.%Line] %Msg%n"/>
                <format id="fmtinfo" format="%Date %Time %LEVEL %Msg%n"/>
            </formats>
        </seelog>
EOT
    fi
    sudo systemctl enable amazon-ssm-agent
fi

################################################################################
### Kernel Params ##############################################################
################################################################################
cat <<EOF | sudo tee /etc/sysctl.d/99-tweaks.conf
fs.file-max = 2097152
fs.nr_open = 2097152

net.core.netdev_max_backlog = 16384
net.core.optmem_max = 16777216
net.core.rmem_default = 262144
net.core.rmem_max = 16777216
net.core.somaxconn = 32768
net.core.wmem_default = 262144
net.core.wmem_max = 16777216

net.netfilter.nf_conntrack_max = 1000000
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.nf_conntrack_max = 1000000

net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_max_tw_buckets = 1048576
EOF

cat /etc/sysctl.conf /etc/sysctl.d/*.conf | sudo sysctl -e -p -


################################################################################
### Cleanup ####################################################################
################################################################################

# Clean up yum caches to reduce the image size
sudo yum clean all
sudo rm -rf \
    $TEMPLATE_DIR  \
    /var/cache/yum

# Clean up files to reduce confusion during debug
sudo rm -rf \
    /etc/hostname \
    /etc/machine-id \
    /etc/resolv.conf \
    /etc/ssh/ssh_host* \
    /home/ec2-user/.ssh/authorized_keys \
    /root/.ssh/authorized_keys \
    /var/lib/cloud/data \
    /var/lib/cloud/instance \
    /var/lib/cloud/instances \
    /var/lib/cloud/sem \
    /var/lib/dhclient/* \
    /var/lib/dhcp/dhclient.* \
    /var/lib/yum/history \
    /var/log/cloud-init-output.log \
    /var/log/cloud-init.log \
    /var/log/secure \
    /var/log/wtmp

sudo touch /etc/machine-id
