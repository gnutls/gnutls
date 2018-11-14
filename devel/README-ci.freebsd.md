# Install a FreeBSD CI instance

```
pkg install -y git gmake bash autoconf gettext libtool automake nettle p11-kit libunistring libtasn1 libidn2 gperf gawk bison softhsm2 openssl cmocka socat wget pkgconf ccache autogen
bash
pw group add -n gitlab-runner
pw user add -n gitlab-runner -g gitlab-runner -s /usr/local/bin/bash
mkdir /home/gitlab-runner
chown gitlab-runner:gitlab-runner /home/gitlab-runner
wget -O /usr/local/bin/gitlab-runner https://gitlab-ci-multi-runner-downloads.s3.amazonaws.com/latest/binaries/gitlab-ci-multi-runner-freebsd-amd64
chmod +x /usr/local/bin/gitlab-runner
touch /var/log/gitlab_runner.log && chown gitlab-runner:gitlab-runner /var/log/gitlab_runner.log
mkdir -p /usr/local/etc/rc.d
cat > /usr/local/etc/rc.d/gitlab_runner << "EOF"
#!/usr/local/bin/bash
# PROVIDE: gitlab_runner
# REQUIRE: DAEMON NETWORKING
# BEFORE:
# KEYWORD:

. /etc/rc.subr

name="gitlab_runner"
rcvar="gitlab_runner_enable"

load_rc_config $name

user="gitlab-runner"
user_home="/home/gitlab-runner"
command="/usr/local/bin/gitlab-runner run"
pidfile="/var/run/${name}.pid"

start_cmd="gitlab_runner_start"
stop_cmd="gitlab_runner_stop"
status_cmd="gitlab_runner_status"

gitlab_runner_start()
{
    export USER=${user}
    export HOME=${user_home}
    export GNULIB_SRCDIR=/builds/common/gnulib
    export GNULIB_TOOL=/builds/common/gnulib/gnulib-tool

    if checkyesno ${rcvar}; then
        cd ${user_home}
        /usr/sbin/daemon -u ${user} -p ${pidfile} ${command} > /var/log/gitlab_runner.log 2>&1
    fi
}

gitlab_runner_stop()
{
    if [ -f ${pidfile} ]; then
        kill `cat ${pidfile}`
    fi
}

gitlab_runner_status()
{
    if [ ! -f ${pidfile} ] || kill -0 `cat ${pidfile}`; then
        echo "Service ${name} is not running."
    else
        echo "${name} appears to be running."
    fi
}

run_rc_command $1
EOF
chmod +x /usr/local/etc/rc.d/gitlab_runner
su gitlab-runner -c 'gitlab-runner register'
sysrc -f /etc/rc.conf "gitlab_runner_enable=YES"
service gitlab_runner start
mkdir -p /builds/common
git clone https://git.savannah.gnu.org/git/gnulib.git /builds/common/gnulib

```

