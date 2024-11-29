---
comment: True
counter: True
---

# Shell 命令备忘

!!! abstract 
    主要是在配置新环境的时候要做的一些事情

## zsh 相关
### 安装
- mac 自带
- Linux 使用对应软件包管理器安装 zsh 即可
    - `sudo apt install zsh`
- 查看 zsh 路径：`which zsh`
- 更改默认 shell：`sudo chsh -s /usr/bin/zsh`

### 主题
- 安装 oh-my-zsh（四选一）
    - `sh -c "$(curl -fsSL https://raw.github.com/robbyrussell/oh-my-zsh/master/tools/install.sh)"`
    - `sh -c "$(curl -fsSL https://gitee.com/mirrors/oh-my-zsh/raw/master/tools/install.sh)"`
    - `sh -c "$(wget https://raw.github.com/robbyrussell/oh-my-zsh/master/tools/install.sh -O -)"`
    - `sh -c "$(wget -O- https://gitee.com/pocmon/mirrors/raw/master/tools/install.sh)"`
- 安装 powerlevel10k（p10k）
    - `git clone --depth=1 https://github.com/romkatv/powerlevel10k.git ${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}/themes/powerlevel10k`
    - `git clone --depth=1 https://gitee.com/romkatv/powerlevel10k.git ${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}/themes/powerlevel10k`
    - 在 ~/.zshrc 中设置 ZSH_THEME 为 "powerlevel10k/powerlevel10k"

### 插件
- 自带 git 插件
- zsh-autosuggestions：`git clone https://github.com/zsh-users/zsh-autosuggestions ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions`
- zsh-syntax-highlighting：`git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting`
- 然后在 ~/.zshrc 中设置 plugins=(git zsh-autosuggestions zsh-syntax-highlighting)

### 常用 alias

- 修改 vim 至 nvim
    ```shell
    alias vim='/usr/local/bin/nvim'
    alias ovim='/usr/bin/vim'
    ```
- 用 [:material-github: sharkdp/bat](https://github.com/sharkdp/bat) 替代 cat 实现语法高亮
    ```shell
    # (on macOS) brew install bat
    alias cat='bat -pp'
    ```
    ```shell
    # (on Linux) sudo apt install bat
    alias cat='batcat -pp'
    ``` 
- 设置代理与取消代理
    ```shell
    alias proxy="export https_proxy=http://127.0.0.1:7890 http_proxy=http://127.0.0.1:7890 all_proxy=socks5://127.0.0.1:7890"
    alias noproxy="unset https_proxy http_proxy all_proxy"
    ```
    - orbstack 的虚拟机连接主机的代理：
        ```shell
        alias proxy="export https_proxy=http://host.orb.internal:7890 http_proxy=http://host.orb.internal:7890 all_proxy=socks5://host.orb.internal:7890"
        ```
- ssh 跳板代理快捷开关
    ```shell
    alias sshproxy="sed -i '' 's/# ProxyCommand ssh jump/ProxyCommand ssh jump/g' ~/.ssh/config"
    alias sshnoproxy="sed -i '' 's/ProxyCommand ssh jump/# ProxyCommand ssh jump/g' ~/.ssh/config"
    ```
- 测试代理是否生效
    ```shell
    alias google='curl -v -I https://www.google.com/'
    ```

## conda 环境安装

安装 [miniconda](https://docs.anaconda.com/miniconda/)：

```shell
mkdir -p ~/miniconda
wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh -O ~/miniconda/miniconda.sh
bash ~/miniconda/miniconda.sh -b -u -p ~/miniconda
rm ~/miniconda/miniconda.sh

source ~/miniconda/bin/activate
conda init zsh
# conda init --all 会莫名其妙加其他不存在的 shell 的配置文件，比如创建 fish 的配置之类的
```

所有可用的平台、架构的安装脚本都在 <https://repo.anaconda.com/miniconda/>

## neovim 配置
### 安装

- macOS：Homebrew 上的是新的，可以直接安装：
    ```shell
    brew install neovim
    ```
- Linux：debian / ubuntu 的软件包都很老，要从 [GitHub](https://github.com/neovim/neovim) 安装：
    ```shell
    wget https://github.com/neovim/neovim/releases/latest/download/nvim-linux64.tar.gz
    tar xzvf nvim-linux64.tar.gz
    cd nvim-linux64
    sudo cp -r bin/nvim /usr/local/bin
    sudo cp -r lib/nvim /usr/local/lib
    sudo cp -r share/nvim /usr/local/share
    ```

### 配置

- 下载配置文件：我的 nvim 配置文件在 [:material-github: TonyCrane/nvim-config](https://github.com/TonyCrane/nvim-config)
    ```shell
    cd ~/.config
    git clone https://github.com/TonyCrane/nvim-config.git nvim
    ```
- 安装 [packer.nvim](https://github.com/wbthomason/packer.nvim)：
    ```shell
    git clone --depth 1 https://github.com/wbthomason/packer.nvim\
    ~/.local/share/nvim/site/pack/packer/start/packer.nvim
    ```
- 打开 nvim 跳过所有报错，执行 `:PackerSync` 安装插件

### 简要 vim 配置

在不想装 nvim 的服务器上临时用 vim 的简单配置：

```vim
syntax on
set expandtab
set number
set autoindent
set smartindent
set tabstop=4
set shiftwidth=4
set softtabstop=4
set laststatus=2
set mouse=a
set scrolloff=4
inoremap { {}<ESC>i
inoremap {<CR> {<CR>}<ESC>O
```
