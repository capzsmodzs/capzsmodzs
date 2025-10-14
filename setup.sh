#!/bin/bash
GREEN=$'\033[1;32m'
RED=$'\033[1;31m'
RESET=$'\033[0m'
REPO="https://raw.githubusercontent.com/capzsmodzs/capzsmodzs/main/"
start=$(date +%s)
TOTAL_STEPS=24
CURRENT_STEP=0

USE_COLOR=1
if [[ ${FORCE_COLOR:-0} == 1 ]]; then
    USE_COLOR=1
elif [[ ! -t 1 || ${NO_COLOR:-0} == 1 ]]; then
    USE_COLOR=0
fi
if (( USE_COLOR == 0 )); then
    GREEN=""
    RED=""
    RESET=""
fi


print_install() {
    CURRENT_STEP=$((CURRENT_STEP + 1))
    if (( USE_COLOR )); then
        printf "%b[%02d/%02d] %s%b\n" "$GREEN" "${CURRENT_STEP}" "${TOTAL_STEPS}" "$1" "$RESET"
    else
        printf "[%02d/%02d] %s\n" "${CURRENT_STEP}" "${TOTAL_STEPS}" "$1"
    fi
}

print_success() {
    if (( USE_COLOR )); then
        printf "    %b[OK]%b %s\n" "$GREEN" "$RESET" "$1"
    else
        printf "    [OK] %s\n" "$1"
    fi
}

print_error() {
    if (( USE_COLOR )); then
        printf "    %b[ERR]%b %s\n" "$RED" "$RESET" "$1"
    else
        printf "    [ERR] %s\n" "$1"
    fi
}

print_ok() {
    if (( USE_COLOR )); then
        printf "    %b[INFO]%b %s\n" "$GREEN" "$RESET" "$1"
    else
        printf "    [INFO] %s\n" "$1"
    fi
}

secs_to_human() {
    local total=$1
    local h=$((total / 3600))
    local m=$(((total % 3600) / 60))
    local s=$((total % 60))
    printf "%02d:%02d:%02d\n" "$h" "$m" "$s"
}

get_public_ip() {
    if ! command -v curl >/dev/null 2>&1; then
        return 1
    fi
    local endpoints=(
        "https://ipinfo.io/ip"
        "https://ipv4.icanhazip.com"
        "https://ifconfig.me/ip"
    )
    local result
    for url in "${endpoints[@]}"; do
        result=$(curl -4 -s --max-time 5 "$url" 2>/dev/null | tr -d '[:space:]')
        if [[ $result =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            echo "$result"
            return 0
        fi
    done
    return 1
}

maybe_clear() {
    if [[ -t 1 && ${NO_CLEAR:-0} -ne 1 ]]; then
        command clear
    fi
}

CF_ZONE="capzsmodzs.biz.id"
CF_TOKEN="${CF_TOKEN:-m-0iXAdPSeUnfaIXUMl3j0HTlsizzz0trgRyPUH1}"
CF_API_BASE="https://api.cloudflare.com/client/v4"

export DEBIAN_FRONTEND="${DEBIAN_FRONTEND:-noninteractive}"

function show_intro_banner() {
    maybe_clear
    local current_ip=${IP:-}
    if [[ -z $current_ip ]]; then
        current_ip=$(get_public_ip || true)
        if [[ -n $current_ip ]]; then
            export IP=$current_ip
        fi
    fi
    local os_name
    os_name=$(awk -F= '/^PRETTY_NAME=/{gsub(/"/,"",$2);print $2}' /etc/os-release)
    if (( USE_COLOR )); then
        printf "%bcapzsmodzs Premium Installer%b\n" "$GREEN" "$RESET"
        printf "%b------------------------------------------------------------%b\n" "$GREEN" "$RESET"
        printf "%b  %-16s : %s%b\n" "$GREEN" "Developer" "capzsmodzs" "$RESET"
        printf "%b  %-16s : %s%b\n" "$GREEN" "Edition" "Premium" "$RESET"
        printf "%b  %-16s : %s%b\n" "$GREEN" "Maintainer" "capzsmodzs" "$RESET"
        printf "%b------------------------------------------------------------%b\n" "$GREEN" "$RESET"
        printf "%b  %-16s : %s%b\n" "$GREEN" "Architecture" "$(uname -m)" "$RESET"
        printf "%b  %-16s : %s%b\n" "$GREEN" "Operating System" "$os_name" "$RESET"
        if [[ -n $current_ip ]]; then
            printf "%b  %-16s : %s%b\n" "$GREEN" "Public IP" "$current_ip" "$RESET"
        else
            printf "%b  %-16s : Unknown%b\n" "$RED" "Public IP" "$RESET"
        fi
        printf "%bPress Enter to start installation:%b " "$GREEN" "$RESET"
    else
        echo "capzsmodzs Premium Installer"
        echo "------------------------------------------------------------"
        printf "  %-16s : %s\n" "Developer" "capzsmodzs"
        printf "  %-16s : %s\n" "Edition" "Premium"
        printf "  %-16s : %s\n" "Maintainer" "capzsmodzs"
        echo "------------------------------------------------------------"
        printf "  %-16s : %s\n" "Architecture" "$(uname -m)"
        printf "  %-16s : %s\n" "Operating System" "$os_name"
        printf "  %-16s : %s\n" "Public IP" "${current_ip:-Unknown}"
        printf "Press Enter to start installation: "
    fi
    read -r
    echo
}
function validate_system() {
    local arch=$(uname -m)
    if [[ ${arch} != "x86_64" ]]; then
        print_error "Architecture ${arch} tidak didukung. Gunakan server x86_64."
        exit 1
    fi

    local os_id
    os_id=$(awk -F= '/^ID=/{gsub(/"/,"",$2);print $2}' /etc/os-release)
    if [[ ${os_id} != "ubuntu" && ${os_id} != "debian" ]]; then
        local os_name=$(awk -F= '/^PRETTY_NAME=/{gsub(/"/,"",$2);print $2}' /etc/os-release)
        print_error "OS ${os_name} tidak didukung oleh script ini."
        exit 1
    fi

    if [[ -z ${IP} ]]; then
        print_error "IP publik tidak terdeteksi. Pastikan VPS memiliki koneksi internet."
        exit 1
    fi
}

function create_cloudflare_record() {
    local subdomain="$1"
    local ip_address="${2:-$(curl -sS ifconfig.me)}"
    local fqdn="${subdomain}.${CF_ZONE}"
    local headers=(-H "Authorization: Bearer ${CF_TOKEN}" -H "Content-Type: application/json")

    local zone_id
    zone_id=$(curl -sS "${CF_API_BASE}/zones?name=${CF_ZONE}&status=active" "${headers[@]}" | jq -r '.result[0].id')
    if [[ -z ${zone_id} || ${zone_id} == "null" ]]; then
        print_error "Gagal mendapatkan Zone ID Cloudflare (${CF_ZONE})."
        exit 1
    fi

    local record_id
    record_id=$(curl -sS "${CF_API_BASE}/zones/${zone_id}/dns_records?name=${fqdn}" "${headers[@]}" | jq -r '.result[0].id')

    local payload
    payload=$(jq -n --arg type "A" --arg name "${fqdn}" --arg content "${ip_address}" '{type:$type,name:$name,content:$content,ttl:120,proxied:false}')

    if [[ -z ${record_id} || ${record_id} == "null" ]]; then
        curl -sS -X POST "${CF_API_BASE}/zones/${zone_id}/dns_records" "${headers[@]}" --data "${payload}" >/dev/null
    else
        curl -sS -X PUT "${CF_API_BASE}/zones/${zone_id}/dns_records/${record_id}" "${headers[@]}" --data "${payload}" >/dev/null
    fi

    echo "${fqdn}"
}

function ensure_netfilter_support() {
    if ! command -v netfilter-persistent >/dev/null 2>&1; then
        apt-get update >/dev/null 2>&1 || true
        apt-get install -y iptables-persistent netfilter-persistent >/dev/null 2>&1 || true
    fi
}

function detect_network_interface() {
    if [[ -n ${NET:-} && -d "/sys/class/net/${NET}" ]]; then
        return
    fi

    NET=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
    if [[ -z ${NET} ]]; then
        NET=$(ip -o link show | awk -F': ' '$2 != "lo" {print $2; exit}')
    fi

    if [[ -z ${NET} ]]; then
        print_error "Gagal mendeteksi interface jaringan default. Vnstat tidak dapat dikonfigurasi otomatis."
    else
        export NET
        print_ok "Interface jaringan default terdeteksi: ${NET}"
    fi
}

### Cek root
function is_root() {
    if [[ 0 == "$UID" ]]; then
        print_ok "Root user Start installation process"
    else
        print_error "The current user is not the root user, please switch to the root user and run the script again"
    fi

}

# Buat direktori xray
function prepare_environment() {
    print_install "Membuat direktori xray"
    mkdir -p /etc/xray
    curl -s ifconfig.me >/etc/xray/ipvps
    touch /etc/xray/domain
    mkdir -p /var/log/xray
    chown www-data.www-data /var/log/xray
    chmod +x /var/log/xray
    touch /var/log/xray/access.log
    touch /var/log/xray/error.log
    mkdir -p /var/lib/kyt >/dev/null 2>&1
    local mem_used=0
    local mem_total=0
    while IFS=":" read -r a b; do
        case $a in
        "MemTotal")
            ((mem_used += ${b/kB/}))
            mem_total="${b/kB/}"
            ;;
        "Shmem") ((mem_used += ${b/kB/})) ;;
        "MemFree" | "Buffers" | "Cached" | "SReclaimable")
            mem_used="$((mem_used -= ${b/kB/}))"
            ;;
        esac
    done </proc/meminfo
    export Ram_Usage="$((mem_used / 1024))"
    export Ram_Total="$((mem_total / 1024))"
    tanggal=$(date -d "0 days" +"%d-%m-%Y - %X")
    export tanggal
    OS_Name=$(awk -F= '/^PRETTY_NAME/{gsub(/"/,"",$2);print $2}' /etc/os-release)
    export OS_Name
    Kernel=$(uname -r)
    export Kernel
    Arch=$(uname -m)
    export Arch
    IP=$(get_public_ip || true)
    if [[ -n $IP ]]; then
        export IP
    fi
}

# Change Environment System
function first_setup() {
    timedatectl set-timezone Asia/Jakarta
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    print_success "Directory Xray"
    local os_id
    os_id=$(awk -F= '/^ID=/{gsub(/"/,""); print $2}' /etc/os-release)
    local version_id
    version_id=$(awk -F= '/^VERSION_ID=/{gsub(/"/,""); print $2}' /etc/os-release)
    local os_pretty
    os_pretty=$(awk -F= '/^PRETTY_NAME=/{gsub(/"/,""); print $2}' /etc/os-release)
    if [[ ${os_id} == "ubuntu" ]]; then
        print_ok "Setup Dependencies ${os_pretty}"
        sudo apt update -y
        apt-get install --no-install-recommends software-properties-common
        if dpkg --compare-versions "${version_id}" lt "22.04"; then
            add-apt-repository ppa:vbernat/haproxy-2.0 -y
            apt-get -y install haproxy=2.0.\*
        else
            apt-get -y install haproxy
        fi
    elif [[ ${os_id} == "debian" ]]; then
        print_ok "Setup Dependencies Untuk ${os_pretty}"
        curl https://haproxy.debian.net/bernat.debian.org.gpg |
            gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg
        echo deb "[signed-by=/usr/share/keyrings/haproxy.debian.net.gpg]" \
            http://haproxy.debian.net buster-backports-1.8 main \
            >/etc/apt/sources.list.d/haproxy.list
        sudo apt-get update
        apt-get -y install haproxy=1.8.\*
    else
        print_error "Your OS is not supported (${os_pretty})."
        exit 1
    fi
}

# GEO PROJECT
function nginx_install() {
    # // Checking System
    if [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "ubuntu" ]]; then
        print_install "Setup nginx For OS Is $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')"
        # // sudo add-apt-repository ppa:nginx/stable -y
        sudo apt-get install nginx -y
    elif [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "debian" ]]; then
        print_success "Setup nginx For OS Is $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')"
        apt -y install nginx
    else
        print_error "OS tidak didukung untuk instalasi nginx otomatis."
    fi
}

# Update and remove packages
function base_package() {
    ########
    print_install "Menginstall Packet Yang Dibutuhkan"
    apt install zip pwgen openssl netcat socat cron bash-completion -y
    apt install figlet -y
    apt update -y
    apt upgrade -y
    apt dist-upgrade -y
    if systemctl list-unit-files | grep -qw '^chronyd.service'; then
        systemctl enable chronyd
        systemctl restart chronyd
    fi
    if systemctl list-unit-files | grep -qw '^chrony.service'; then
        systemctl enable chrony
        systemctl restart chrony
    fi
    chronyc sourcestats -v
    chronyc tracking -v
    apt install ntpdate -y
    ntpdate pool.ntp.org
    apt install sudo -y
    sudo apt-get clean all
    sudo apt-get autoremove -y
    sudo apt-get install -y debconf-utils
    sudo apt-get remove --purge exim4 -y
    sudo apt-get remove --purge ufw firewalld -y
    sudo apt-get install -y --no-install-recommends software-properties-common
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    sudo apt-get install -y speedtest-cli vnstat libnss3-dev libnspr4-dev pkg-config libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev libcurl4-nss-dev flex bison make libnss3-tools libevent-dev bc rsyslog dos2unix zlib1g-dev libssl-dev libsqlite3-dev sed dirmngr libxml-parser-perl build-essential gcc g++ python htop lsof tar wget curl ruby zip unzip p7zip-full python3-pip libc6 util-linux build-essential msmtp-mta ca-certificates bsd-mailx iptables iptables-persistent netfilter-persistent net-tools openssl ca-certificates gnupg gnupg2 ca-certificates lsb-release gcc shc make cmake git screen socat xz-utils apt-transport-https gnupg1 dnsutils cron bash-completion ntpdate chrony jq openvpn easy-rsa
    ensure_netfilter_support
    print_success "Packet Yang Dibutuhkan"

}
# Fungsi input domain
function pasang_domain() {
    echo -e ""
    print_install "Menentukan domain otomatis via Cloudflare"
    local random_subdomain
    random_subdomain=$(tr -dc 'a-z0-9' </dev/urandom | head -c6)
    local fqdn
    fqdn=$(create_cloudflare_record "${random_subdomain}")
    mkdir -p /root/xray
    echo "${fqdn}" >/root/domain
    echo "${fqdn}" >/root/scdomain
    echo "${fqdn}" >/etc/xray/domain
    echo "${fqdn}" >/etc/v2ray/domain
    echo "${fqdn}" >/etc/xray/scdomain
    echo "IP=${fqdn}" >/var/lib/kyt/ipvps.conf
    print_ok "Domain otomatis digunakan: ${fqdn}"
    sleep 2
}

#GANTI PASSWORD DEFAULT
function password_default() {
    print_install "Konfigurasi Password Root"
    read -rp "Ingin mengganti password root sekarang? [y/N]: " change_root
    if [[ ${change_root,,} == "y" ]]; then
        if passwd root; then
            print_ok "Password root berhasil diperbarui"
        else
            print_error "Penggantian password root dibatalkan atau gagal"
        fi
    else
        print_ok "Penggantian password root dilewati"
    fi
    true
    print_success "Konfigurasi Password Root"
}

restart_system() {
    #IZIN SCRIPT
    MYIP=$(curl -sS ipv4.icanhazip.com)
    if (( USE_COLOR )); then
        printf "%sloading...%s\n" "$GREEN" "$RESET"
    else
        echo "loading..."
    fi
    izinsc="https://raw.githubusercontent.com/capzsmodzs/capzsmodzs/main/register"
    # USERNAME
    rm -f /usr/bin/user
    username=$(curl $izinsc | grep $MYIP | awk '{print $2}')
    echo "$username" >/usr/bin/user
    expx=$(curl $izinsc | grep $MYIP | awk '{print $3}')
    echo "$expx" >/usr/bin/e
    # DETAIL ORDER
    username=$(cat /usr/bin/user)
    if [[ -f /usr/bin/ver ]]; then
        oid=$(cat /usr/bin/ver)
    else
        oid="-"
    fi
    exp=$(cat /usr/bin/e)
    domain=$(cat /etc/xray/domain 2>/dev/null)
    today=$(date +'%Y-%m-%d')
    DATE="$today"
    valid="$exp"
    ISP=$(curl -s ipinfo.io/org | cut -d " " -f 2-10)
    # Status Expired Active
    if (( USE_COLOR )); then
        Info="(${GREEN}Active${RESET})"
        Error="(${RED}Expired${RESET})"
    else
        Info="(Active)"
        Error="(Expired)"
    fi
    if [[ -n $valid && "$today" < "$valid" ]]; then
        sts="${Info}"
    else
        sts="${Error}"
    fi
    TIMES="10"
    CHATID="7622491347"
    KEY="7147889676:AAGneWuFhAWM6V0OO-xa73CDG32C-q5OUgA"
    URL="https://api.telegram.org/bot$KEY/sendMessage"
    TIMEZONE=$(printf '%(%H:%M:%S)T')
    TEXT="
<code>━━━━━━━━━━━━━━━━━━━━━━━━━</code>
<b>PREMIUM AUTOSCRIPT</b>
<code>━━━━━━━━━━━━━━━━━━━━━━━━━</code>
<code>User     :</code><code>$username</code>
<code>Domain   :</code><code>$domain</code>
<code>IPVPS    :</code><code>$MYIP</code>
<code>ISP      :</code><code>$ISP</code>
<code>DATE     :</code><code>$DATE</code>
<code>Time     :</code><code>$TIMEZONE</code>
<code>Exp Sc.  :</code><code>$exp</code>
<code>━━━━━━━━━━━━━━━━━━━━━━━━━</code>
<i>Automatic Notifications From Github</i>
"'&reply_markup={"inline_keyboard":[[{"text":"ᴏʀᴅᴇʀ","url":"http://t.me/imamRydi8"}]]}'

    curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null
}
# Pasang SSL
function pasang_ssl() {
    print_install "Memasang SSL Pada Domain"
    rm -rf /etc/xray/xray.key
    rm -rf /etc/xray/xray.crt
    domain=$(cat /root/domain)
    STOPWEBSERVER=$(lsof -i:80 | awk 'NR==2 {print $1}')
    rm -rf /root/.acme.sh
    mkdir /root/.acme.sh
    if [[ -n $STOPWEBSERVER && $STOPWEBSERVER != "COMMAND" ]]; then
        systemctl stop "$STOPWEBSERVER" >/dev/null 2>&1 || true
    fi
    systemctl stop nginx >/dev/null 2>&1 || true
    curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
    chmod +x /root/.acme.sh/acme.sh
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    /root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
    ~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
    chmod 777 /etc/xray/xray.key
    print_success "SSL Certificate"
}

function make_folder_xray() {
    rm -rf /etc/vmess/.vmess.db
    rm -rf /etc/vless/.vless.db
    rm -rf /etc/trojan/.trojan.db
    rm -rf /etc/shadowsocks/.shadowsocks.db
    rm -rf /etc/ssh/.ssh.db
    rm -rf /etc/bot/.bot.db
    rm -rf /etc/user-create/user.log
    mkdir -p /etc/bot
    mkdir -p /etc/xray
    mkdir -p /etc/vmess
    mkdir -p /etc/vless
    mkdir -p /etc/trojan
    mkdir -p /etc/shadowsocks
    mkdir -p /etc/ssh
    mkdir -p /usr/bin/xray/
    mkdir -p /var/log/xray/
    mkdir -p /var/www/html
    mkdir -p /etc/kyt/limit/vmess/ip
    mkdir -p /etc/kyt/limit/vless/ip
    mkdir -p /etc/kyt/limit/trojan/ip
    mkdir -p /etc/kyt/limit/ssh/ip
    mkdir -p /etc/limit/vmess
    mkdir -p /etc/limit/vless
    mkdir -p /etc/limit/trojan
    mkdir -p /etc/limit/ssh
    mkdir -p /etc/user-create
    chmod +x /var/log/xray
    touch /etc/xray/domain
    touch /var/log/xray/access.log
    touch /var/log/xray/error.log
    touch /etc/vmess/.vmess.db
    touch /etc/vless/.vless.db
    touch /etc/trojan/.trojan.db
    touch /etc/shadowsocks/.shadowsocks.db
    touch /etc/ssh/.ssh.db
    touch /etc/bot/.bot.db
    echo "& plughin Account" >>/etc/vmess/.vmess.db
    echo "& plughin Account" >>/etc/vless/.vless.db
    echo "& plughin Account" >>/etc/trojan/.trojan.db
    echo "& plughin Account" >>/etc/shadowsocks/.shadowsocks.db
    echo "& plughin Account" >>/etc/ssh/.ssh.db
    echo "echo -e 'Vps Config User Account'" >>/etc/user-create/user.log
}
#Instal Xray
function install_xray() {
    print_install "Core Xray 1.8.1 Latest Version"
    domainSock_dir="/run/xray"
    ! [ -d $domainSock_dir ] && mkdir $domainSock_dir
    chown www-data.www-data $domainSock_dir

    # / / Ambil Xray Core Version Terbaru
    #latest_version="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version 1.8.1

    # // Ambil Config Server
    wget -O /etc/xray/config.json "${REPO}config/config.json" >/dev/null 2>&1
    wget -O /etc/systemd/system/runn.service "${REPO}files/runn.service" >/dev/null 2>&1
    #chmod +x /usr/local/bin/xray
    domain=$(cat /etc/xray/domain)
    IPVS=$(cat /etc/xray/ipvps)
    print_success "Core Xray 1.8.1 Latest Version"

    # Settings UP Nginix Server
    curl -s ipinfo.io/city >>/etc/xray/city
    curl -s ipinfo.io/org | cut -d " " -f 2-10 >>/etc/xray/isp
    print_install "Memasang Konfigurasi Packet"
    wget -O /etc/haproxy/haproxy.cfg "${REPO}config/haproxy.cfg" >/dev/null 2>&1
    wget -O /etc/nginx/conf.d/xray.conf "${REPO}config/xray.conf" >/dev/null 2>&1
    sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
    sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf
    curl ${REPO}config/nginx.conf >/etc/nginx/nginx.conf

    cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/hap.pem

    # > Set Permission
    chmod +x /etc/systemd/system/runn.service

    # > Create Service
    rm -rf /etc/systemd/system/xray.service.d
    cat >/etc/systemd/system/xray.service <<EOF
Description=Xray Service
Documentation=https://github.com
After=network.target nss-lookup.target

[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target

EOF
    print_success "Konfigurasi Packet"
}

function configure_ssh() {
    print_install "Memasang Password SSH"
    wget -O /etc/pam.d/common-password "${REPO}files/password"
    chmod +x /etc/pam.d/common-password

    # go to root
    cd

    # Edit file /etc/systemd/system/rc-local.service
    cat >/etc/systemd/system/rc-local.service <<-END
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
END

    # nano /etc/rc.local
    cat >/etc/rc.local <<-END
#!/bin/sh -e
# rc.local
# By default this script does nothing.
exit 0
END

    # Ubah izin akses
    chmod +x /etc/rc.local

    # enable rc local
    systemctl enable rc-local
    systemctl start rc-local.service

    # disable ipv6
    echo 1 >/proc/sys/net/ipv6/conf/all/disable_ipv6
    sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

    #update
    # set time GMT +7
    ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

    # set locale
    sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
    print_success "Password SSH"
}

function udp_mini() {
    print_install "Memasang Service Limit IP & Quota"
    wget -q https://raw.githubusercontent.com/capzsmodzs/capzsmodzs/main/config/fv-tunnel && chmod +x fv-tunnel && ./fv-tunnel

    # // Installing UDP Mini
    mkdir -p /usr/local/kyt/
    wget -q -O /usr/local/kyt/udp-mini "${REPO}files/udp-mini"
    chmod +x /usr/local/kyt/udp-mini
    wget -q -O /etc/systemd/system/udp-mini-1.service "${REPO}files/udp-mini-1.service"
    wget -q -O /etc/systemd/system/udp-mini-2.service "${REPO}files/udp-mini-2.service"
    wget -q -O /etc/systemd/system/udp-mini-3.service "${REPO}files/udp-mini-3.service"
    systemctl disable udp-mini-1
    systemctl stop udp-mini-1
    systemctl enable udp-mini-1
    systemctl start udp-mini-1
    systemctl disable udp-mini-2
    systemctl stop udp-mini-2
    systemctl enable udp-mini-2
    systemctl start udp-mini-2
    systemctl disable udp-mini-3
    systemctl stop udp-mini-3
    systemctl enable udp-mini-3
    systemctl start udp-mini-3
    print_success "Limit IP Service"
}

function ssh_slow() {
    # // Installing UDP Mini
    print_install "Memasang modul SlowDNS Server"
    wget -q -O /tmp/nameserver "${REPO}files/nameserver" >/dev/null 2>&1
    chmod +x /tmp/nameserver
    bash /tmp/nameserver | tee /root/install.log
    print_success "SlowDNS"
}

function ins_SSHD() {
    print_install "Memasang SSHD"
    wget -q -O /etc/ssh/sshd_config "${REPO}files/sshd" >/dev/null 2>&1
    chmod 700 /etc/ssh/sshd_config
    /etc/init.d/ssh restart
    systemctl restart ssh
    /etc/init.d/ssh status
    print_success "SSHD"
}

function ins_dropbear() {
    print_install "Menginstall Dropbear"
    if [[ ! -f /etc/kyt.txt ]]; then
        cat <<'EOF' >/etc/kyt.txt
capzsmodzs Autoscript Service
EOF
        chmod 644 /etc/kyt.txt
    fi
    # // Installing Dropbear
    apt-get install dropbear -y >/dev/null 2>&1
    wget -q -O /etc/default/dropbear "${REPO}config/dropbear.conf"
    chmod +x /etc/default/dropbear
    if [[ ! -f /etc/dropbear/dropbear_dss_host_key ]]; then
        mkdir -p /etc/dropbear
        if command -v dropbearkey >/dev/null 2>&1; then
            dropbearkey -t dss -f /etc/dropbear/dropbear_dss_host_key >/dev/null 2>&1 || true
        fi
    fi
    /etc/init.d/dropbear restart
    /etc/init.d/dropbear status
    print_success "Dropbear"
}

function ins_vnstat() {
    print_install "Menginstall Vnstat"
    if [[ -z ${NET:-} ]]; then
        print_error "Interface jaringan tidak ditemukan, melewati instalasi Vnstat"
        return 1
    fi
    # setting vnstat
    apt -y install vnstat >/dev/null 2>&1
    /etc/init.d/vnstat restart
    apt -y install libsqlite3-dev >/dev/null 2>&1
    wget https://humdi.net/vnstat/vnstat-2.6.tar.gz
    tar zxvf vnstat-2.6.tar.gz
    cd vnstat-2.6
    ./configure --prefix=/usr --sysconfdir=/etc && make && make install
    cd
    if ! vnstat --create -i "$NET" >/dev/null 2>&1; then
        vnstat --add -i "$NET" >/dev/null 2>&1 || true
    fi
    sed -i 's/Interface "'""eth0""'"/Interface "'""$NET""'"/g' /etc/vnstat.conf
    chown vnstat:vnstat /var/lib/vnstat -R
    systemctl enable vnstat
    /etc/init.d/vnstat restart
    /etc/init.d/vnstat status
    rm -f /root/vnstat-2.6.tar.gz
    rm -rf /root/vnstat-2.6
    print_success "Vnstat"
}

function ins_openvpn() {
    print_install "Menginstall OpenVPN"
    #OpenVPN
    wget ${REPO}files/openvpn && chmod +x openvpn && ./openvpn
    /etc/init.d/openvpn restart
    print_success "OpenVPN"
}

function ins_backup() {
    print_install "Memasang Backup Server"
    #BackupOption
    apt install rclone -y
    printf "q\n" | rclone config
    mkdir -p /root/.config/rclone
    if ! wget -q -O /root/.config/rclone/rclone.conf "${REPO}config/rclone.conf"; then
        cat <<'EOF' >/root/.config/rclone/rclone.conf
[dr]
type = drive
scope = drive
# Isikan token secara lokal via variabel lingkungan atau file yang tidak dilacak Git.
token = {"access_token":"REPLACE_ME","token_type":"Bearer","refresh_token":"REPLACE_ME","expiry":"YYYY-MM-DDTHH:MM:SSZ"}
EOF
        print_ok "Konfigurasi rclone default dibuat secara lokal"
    fi
    #Install Wondershaper
    cd /bin
    git clone https://github.com/magnific0/wondershaper.git
    cd wondershaper
    sudo make install
    cd
    rm -rf wondershaper
    echo >/home/limit
    apt install msmtp-mta ca-certificates bsd-mailx -y
    cat <<'EOF' >/etc/msmtprc
defaults
tls on
tls_starttls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt

account default
host smtp.gmail.com
port 587
auth on
user oceantestdigital@gmail.com
from oceantestdigital@gmail.com
password jokerman77 
logfile ~/.msmtp.log
EOF
    chown root:root /etc/msmtprc
    chmod 600 /etc/msmtprc
    wget -q -O /etc/ipserver "${REPO}files/ipserver" && bash /etc/ipserver
    print_success "Backup Server"
}

function ins_swab() {
    print_install "Memasang Swap 1 G"
    gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
    gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v$gotop_latest/gotop_v"$gotop_latest"_linux_amd64.deb"
    curl -sL "$gotop_link" -o /tmp/gotop.deb
    dpkg -i /tmp/gotop.deb >/dev/null 2>&1

    # > Buat swap sebesar 1G
    dd if=/dev/zero of=/swapfile bs=1024 count=1048576
    mkswap /swapfile
    chown root:root /swapfile
    chmod 0600 /swapfile >/dev/null 2>&1
    swapon /swapfile >/dev/null 2>&1
    sed -i '$ i\/swapfile      swap swap   defaults    0 0' /etc/fstab

    # > Singkronisasi jam
    chronyd -q 'server 0.id.pool.ntp.org iburst'
    chronyc sourcestats -v
    chronyc tracking -v

    wget ${REPO}files/bbr.sh && chmod +x bbr.sh && ./bbr.sh
    print_success "Swap 1 G"
}

function ins_Fail2ban() {
    print_install "Menginstall Fail2ban"
    apt-get install -y fail2ban >/dev/null 2>&1

    # Instal DDOS Flate
    if [ -d '/usr/local/ddos' ]; then
        echo
        echo
        echo "Please un-install the previous version first"
        exit 0
    else
        mkdir /usr/local/ddos
    fi

    # banner
    echo "Banner /etc/kyt.txt" >>/etc/ssh/sshd_config
    sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/kyt.txt"@g' /etc/default/dropbear

    # Ganti Banner
    wget -O /etc/kyt.txt "${REPO}files/issue.net"
    systemctl enable --now fail2ban >/dev/null 2>&1 || true
    systemctl restart fail2ban >/dev/null 2>&1 || true
    print_success "Fail2ban"
}

function ins_epro() {
    print_install "Menginstall ePro WebSocket Proxy"
    wget -O /usr/bin/ws "${REPO}files/ws" >/dev/null 2>&1
    wget -O /usr/bin/tun.conf "${REPO}config/tun.conf" >/dev/null 2>&1
    wget -O /etc/systemd/system/ws.service "${REPO}files/ws.service" >/dev/null 2>&1
    chmod +x /etc/systemd/system/ws.service
    chmod +x /usr/bin/ws
    chmod 644 /usr/bin/tun.conf
    systemctl disable ws
    systemctl stop ws
    systemctl enable ws
    systemctl start ws
    systemctl restart ws
    wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" >/dev/null 2>&1
    wget -q -O /usr/local/share/xray/geoip.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" >/dev/null 2>&1
    wget -O /usr/sbin/ftvpn "${REPO}files/ftvpn" >/dev/null 2>&1
    chmod +x /usr/sbin/ftvpn
    ensure_netfilter_support
    iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
    iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
    iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
    iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
    iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
    iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
    iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
    iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
    iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
    iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
    iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP
    iptables-save >/etc/iptables.up.rules
    iptables-restore -t </etc/iptables.up.rules
    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save >/dev/null 2>&1 || true
        netfilter-persistent reload >/dev/null 2>&1 || true
    fi

    # remove unnecessary files
    cd
    apt autoclean -y >/dev/null 2>&1
    apt autoremove -y >/dev/null 2>&1
    print_success "ePro WebSocket Proxy"
}

function ins_restart() {
    print_install "Restarting  All Packet"
    /etc/init.d/nginx restart
    /etc/init.d/openvpn restart
    /etc/init.d/ssh restart
    /etc/init.d/dropbear restart
    /etc/init.d/vnstat restart
    systemctl restart haproxy
    /etc/init.d/cron restart
    systemctl daemon-reload
    if command -v netfilter-persistent >/dev/null 2>&1; then
        systemctl start netfilter-persistent >/dev/null 2>&1 || true
    fi
    systemctl enable --now nginx
    systemctl enable --now xray
    systemctl enable --now rc-local
    systemctl enable --now dropbear
    systemctl enable --now openvpn
    systemctl enable --now cron
    systemctl enable --now haproxy
    if command -v netfilter-persistent >/dev/null 2>&1; then
        systemctl enable --now netfilter-persistent >/dev/null 2>&1 || true
    fi
    systemctl enable --now ws
    if command -v fail2ban-client >/dev/null 2>&1; then
        systemctl enable --now fail2ban >/dev/null 2>&1 || true
    fi
    history -c
    echo "unset HISTFILE" >>/etc/profile

    cd
    rm -f /root/openvpn
    rm -f /root/key.pem
    rm -f /root/cert.pem
    print_success "All Packet"
}

#Instal Menu
function menu() {
    print_install "Memasang Menu Packet"
    wget ${REPO}menu/menu.zip
    unzip menu.zip
    chmod +x menu/*
    mv menu/* /usr/local/sbin
    rm -rf menu
    rm -rf menu.zip
}

# Membaut Default Menu
function profile() {
    print_install "Menyiapkan profil shell dan jadwal otomatis"
    cat >/root/.profile <<EOF
# ~/.profile: executed by Bourne-compatible login shells.
if [ "$BASH" ]; then
    if [ -f ~/.bashrc ]; then
        . ~/.bashrc
    fi
fi
mesg n || true
menu
EOF

    cat >/etc/cron.d/xp_all <<-END
		SHELL=/bin/sh
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
		2 0 * * * root /usr/local/sbin/xp
	END
    cat >/etc/cron.d/logclean <<-END
		SHELL=/bin/sh
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
		*/20 * * * * root /usr/local/sbin/clearlog
		END
    chmod 644 /root/.profile

    cat >/etc/cron.d/daily_reboot <<-END
		SHELL=/bin/sh
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
		0 5 * * * root /sbin/reboot
	END
    cat >/etc/cron.d/limit_ip <<-END
		SHELL=/bin/sh
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
		*/2 * * * * root /usr/local/sbin/limit-ip
	END
    cat >/etc/cron.d/limit_ip2 <<-END
		SHELL=/bin/sh
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
		*/2 * * * * root /usr/bin/limit-ip
	END
    echo "*/1 * * * * root echo -n > /var/log/nginx/access.log" >/etc/cron.d/log.nginx
    echo "*/1 * * * * root echo -n > /var/log/xray/access.log" >>/etc/cron.d/log.xray
    service cron restart
    cat >/home/daily_reboot <<-END
		5
	END

    cat >/etc/systemd/system/rc-local.service <<EOF
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
EOF

    echo "/bin/false" >>/etc/shells
    echo "/usr/sbin/nologin" >>/etc/shells
    cat >/etc/rc.local <<EOF
#!/bin/sh -e
# rc.local
# By default this script does nothing.
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
systemctl restart netfilter-persistent
exit 0
EOF

    chmod +x /etc/rc.local

    AUTOREB=$(cat /home/daily_reboot)
    SETT=11
    if [ $AUTOREB -gt $SETT ]; then
        TIME_DATE="PM"
    else
        TIME_DATE="AM"
    fi
    print_success "Profil shell dan jadwal otomatis"
}

function show_summary() {
    print_install "Menampilkan ringkasan instalasi"
    local domain="-"
    if [[ -f /etc/xray/domain ]]; then
        domain=$(cat /etc/xray/domain)
    fi
    local public_ip="${IP:-$(get_public_ip || echo "-")}"
    if (( USE_COLOR )); then
        printf "    %b%-18s : %s%b\n" "$GREEN" "Domain aktif" "$domain" "$RESET"
        printf "    %b%-18s : %s%b\n" "$GREEN" "IP publik" "$public_ip" "$RESET"
        printf "    %b%-18s : %s%b\n" "$GREEN" "Folder web" "/var/www/html" "$RESET"
        printf "    %b%-18s : %s%b\n" "$GREEN" "Konfigurasi Xray" "/etc/xray/config.json" "$RESET"
        printf "    %b%-18s : %s%b\n" "$GREEN" "Cert & Key" "/etc/xray/xray.crt /etc/xray/xray.key" "$RESET"
        printf "    %b%-18s :%b\n" "$GREEN" "Status layanan" "$RESET"
    else
        printf "    %-18s : %s\n" "Domain aktif" "$domain"
        printf "    %-18s : %s\n" "IP publik" "$public_ip"
        printf "    %-18s : %s\n" "Folder web" "/var/www/html"
        printf "    %-18s : %s\n" "Konfigurasi Xray" "/etc/xray/config.json"
        printf "    %-18s : %s\n" "Cert & Key" "/etc/xray/xray.crt /etc/xray/xray.key"
        printf "    %-18s :\n" "Status layanan"
    fi
    local services=(nginx xray haproxy dropbear openvpn ws)
    for svc in "${services[@]}"; do
        if systemctl is-active "$svc" >/dev/null 2>&1; then
            if (( USE_COLOR )); then
                printf "        - %-12s : %bRUNNING%b\n" "$svc" "$GREEN" "$RESET"
            else
                printf "        - %-12s : RUNNING\n" "$svc"
            fi
        else
            if (( USE_COLOR )); then
                printf "        - %-12s : %bINACTIVE%b\n" "$svc" "$RED" "$RESET"
            else
                printf "        - %-12s : INACTIVE\n" "$svc"
            fi
        fi
    done
}

# Restart layanan after install
function enable_services() {
    print_install "Enable Service"
    ensure_netfilter_support
    systemctl daemon-reload
    if command -v netfilter-persistent >/dev/null 2>&1; then
        systemctl start netfilter-persistent >/dev/null 2>&1 || true
    fi
    systemctl enable --now rc-local
    systemctl enable --now cron
    if command -v netfilter-persistent >/dev/null 2>&1; then
        systemctl enable --now netfilter-persistent >/dev/null 2>&1 || true
    fi
    systemctl restart nginx
    systemctl restart xray
    systemctl restart cron
    systemctl restart haproxy
    print_success "Enable Service"
}

# Fingsi Install Script
function instal() {
    maybe_clear
    show_intro_banner
    validate_system
    is_root
    prepare_environment
    first_setup
    nginx_install
    base_package
    make_folder_xray
    pasang_domain
    password_default
    pasang_ssl
    install_xray
    configure_ssh
    udp_mini
    ssh_slow
    ins_SSHD
    ins_dropbear
    detect_network_interface
    ins_vnstat
    ins_openvpn
    ins_backup
    ins_swab
    ins_Fail2ban
    ins_epro
    ins_restart
    menu
    profile
    enable_services
    show_summary
    restart_system
}
instal
echo ""
history -c
rm -rf /root/menu
rm -rf /root/*.zip
rm -rf /root/*.sh
rm -rf /root/LICENSE
rm -rf /root/README.md
rm -rf /root/domain
#sudo hostnamectl set-hostname $user
secs_to_human "$(($(date +%s) - ${start}))"
if [[ -n ${username:-} ]]; then
    sudo hostnamectl set-hostname "$username"
else
    print_error "Hostname tidak diubah karena username tidak tersedia"
fi
if (( USE_COLOR )); then
    printf "%sScript Successfully Installed%s\n" "$GREEN" "$RESET"
else
    echo "Script Successfully Installed"
fi
echo ""
if (( USE_COLOR )); then
    read -p "$(printf "%sPress Enter to reboot%s " "$GREEN" "$RESET")"
else
    read -p "Press Enter to reboot "
fi
reboot
