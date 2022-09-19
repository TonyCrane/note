---
counter: True
comment: True
---

# Git 命令备忘

!!! abstract
    一些常用/常忘的 git 命令

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

## 清除命令
- `git rm --cached <file>`：已 add 未 commit 的文件退回未 add 状态
- `git checkout -- <file>`：已修改的文件撤销修改
- `git reset --soft HEAD^`：撤销 commit（不更改文件）
- `git reset --hard HEAD^`：撤销 commit（文件回退到上一版本）
- `git update-ref -d HEAD`：撤销第一条 commit（不更改文件）
- `git push -f`：强制推送，覆盖 commit