---
counter: True
comment: True
---

# Git 相关使用与配置

!!! abstract
    一些常用/常忘的 git 命令，和基础的配置

## 基础命令
### 分支
- `git checkout -b <branch_name>`：创建分支，并切换过去
- `git checkout master`：回到主分支
- `git push origin <branch_name>`：将分支推送到远程仓库
- `git pull`：将本地仓库更新
- `git diff <branch_name> master`：显示差别

### 克隆分支
- `git clone -b <branch_name> <repo_url>`：克隆单个分支
- `git branch -a`：查看所有分支
- `git checkout -b <branch_name> origin/<branch_name>`：关联分支

### 清除命令
- `git rm --cached <file>`：已 add 未 commit 的文件退回未 add 状态
- `git checkout -- <file>`：已修改的文件撤销修改
- `git reset --soft HEAD^`：撤销 commit（不更改文件）
- `git reset --hard HEAD^`：撤销 commit（文件回退到上一版本）
- `git update-ref -d HEAD`：撤销第一条 commit（不更改文件）
- `git push -f`：强制推送，覆盖 commit

## gpg 签署 commit
### 生成 gpg 密钥

```shell    
gpg --full-generate-key
```

默认即可（ECC ed25519 签名和加密），签名其实就够，但 ed25519 本来就没多长，再加一个加密可以等以后用。

接着需要拿到 key id（fingerprint 的末尾字节），ed25519 斜杠后面的就是 key id：

```shell
gpg --list-secret-keys --keyid-format=long
```

然后需要将公钥上传到 github：

```shell
gpg --armor --export <key_id>
```

### 导入导出 gpg 密钥

在不同的设备上用同一个 gpg key 需要导出导入密钥：

```shell
gpg -a -o private.key --export-secret-keys <key_id>
...
gpg --import private.key
```

但是 uid 是不受信任的，可以 `gpg --edit-key <key_id>` 之后 trust 再保存就好了。

### git 配置 gpg

新机器的话直接改 `~/.gitconfig` 就好了：

```toml
[user]
    name = <name>
    email = <email>
    signingkey = <keyid>
[commit]
    gpgsign = true
[gpg]
    program = /usr/bin/gpg
[init]
    defaultBranch = master
```

这样就可以默认签署 commit 了。

### macOS 通过钥匙环无感签署

macOS 可以通过 [pinentry-mac](https://formulae.brew.sh/formula/pinentry-mac) 记住密码来无感签署 commit：

```shell
brew install pinentry-mac
echo "pinentry-program /opt/homebrew/bin/pinentry-mac" >> ~/.gnupg/gpg-agent.conf
killall gpg-agent
```

第一次会要求输入密码，记住之后以后就不用再输入了，而且也不需要依靠 `GPG_TTY` 环境变量了。

### GPG_TTY 环境变量

有些时候导入导出密钥、签署 commit 等需要用到 gpg 的时候莫名其妙报 no such file 之类的错误，或者签署失败，大概率是因为 `GPG_TTY` 环境变量导致的，可以手动重新设置一下就好：

```shell
export GPG_TTY=$(tty)
```

## GitHub CLI

在修改 PR 之类的时候用 GitHub CLI 可以方便一点，而且在 Linux 上通过 http 访问 GitHub 私有库需要权限的时候也可以由 GitHub CLI 提供，所以还是可以安装的。

### 安装

- macOS 直接 Homebrew 安装：
    ```shell
    brew install gh
    ```
- Linux 需要根据[官方指南](https://github.com/cli/cli/blob/trunk/docs/install_linux.md)来添加软件源手动安装：
    ```shell
    (type -p wget >/dev/null || (sudo apt update && sudo apt-get install wget -y)) \
        && sudo mkdir -p -m 755 /etc/apt/keyrings \
        && wget -qO- https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo tee /etc/apt/keyrings/githubcli-archive-keyring.gpg > /dev/null \
        && sudo chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg \
        && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
        && sudo apt update \
        && sudo apt install gh -y
    ```

### 登录

```shell
gh auth login
```

在浏览器打开链接登录后输入 device code 就可以了，然后会自动在 `~/.gitconfig` 中添加：

```toml
[credential "https://github.com"]
	helper =
	helper = !/usr/bin/gh auth git-credential
[credential "https://gist.github.com"]
	helper =
	helper = !/usr/bin/gh auth git-credential
```

这样之后 clone push 私有库什么的就不需要再登录了。