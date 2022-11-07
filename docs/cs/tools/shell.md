---
comment: True
counter: True
---

# Shell 命令备忘

!!! abstract 
    一些常用的 shell 命令，目前应该补全，想起来就更新吧

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