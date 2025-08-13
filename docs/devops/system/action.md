---
comment: True
counter: True
---

# GitHub Actions 基础与运用

!!! abstract
    GitHub Actions workflow 文件的常用写法记录

## workflow 语法

一般结构：

```yaml
name: <workflow name> # 出现在 Actions 列表中
on:             # 触发条件
  ...
permissions:    # 权限设置
  ...
concurrency:    # 并发控制
  ...
jobs:           # 任务列表
  <job name>:   # 任务名
    runs-on: <os> # 运行环境
    steps:      # steps 会依次执行
      - name: <step name> # 步骤名，可省略
        uses: <action> # 使用的 action
        with:          # 传递给 action 的参数
          ...
      - name: <step name>
        run: <command> # 直接运行命令
        env:           # 传递环境变量
          <key>: <value>
```

### trigger

何时触发 action 运行，常用：

```yaml
on:
  push:
    branches: [master, dev] # 推送到 master 或 dev 分支时触发
  pull_request:
    types: [opened, reopened, synchronize] # PR 创建、重新打开或更新时触发
  schedule:
    - cron: "0 0/24 * * *" # 定时任务，每 24 小时运行一次
  workflow_dispatch: # 手动触发（在 Action 页面可以点击运行）
```

注意 pull_request 事件是在 PR 的源仓库上运行，pull_request_target 是在目标仓库上运行，二者支持的权限不一样。

### jobs

这部分是 workflow 核心，依次写步骤即可，可以用 uses 使用现成的 action，也可以用 run 直接运行命令。这里只记录一些其他用法。

#### 不同运行环境和版本搭配

```yaml
jobs:
  job:
    strategy:
      matrix: # 会创建六个 job 并行运行
        os: [ubuntu-latest, macos-latest]
        version: [10, 12, 14]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/setup-node@v4
        with:
          node-version: ${{ matrix.version }}
```

#### 条件执行

```yaml
jobs:
  job:
    runs-on: ubuntu-latest
    steps:
      - run: ...
        if: ${{ !contains(github.event.head_commit.message, '[skip ci]') }} # 如果提交信息不包含 [skip ci] 则运行
        # job 也可以有 if 语句
```

更多可用上下文环境见 [GitHub Actions docs > Reference > Contexts](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#github-context)。

#### 多 job 依赖

类似 docker-compose depends_on：

```yaml
jobs:
  job1:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Job 1"
  job2:
    runs-on: ubuntu-latest
    needs: job1 # 等待 job1 完成后再运行，不加的话会并行运行
    steps:
      - run: echo "Job 2"
```

#### steps 间传递数据

通过环境变量传递：

```yaml
steps:
  - run: |
    export FOO=bar
    echo "::set-env name=FOO::$FOO" # 设置环境变量
  - run: echo $FOO # 可以直接使用环境变量
# or
steps:
  - run: |
    echo "FOO=bar" >> $GITHUB_ENV # 设置环境变量
  - run: echo ${{ env.FOO }}
```

通过 outputs 传递：

```yaml
steps:
  - id: step1
    run: echo "::set-output name=foo::bar"
  - run: echo "${{ steps.step1.outputs.foo }}"
# or
steps:
  - id: step1
    run: echo "foo=bar" >> $GITHUB_OUTPUT # 设置输出变量
  - run: echo "${{ steps.step1.outputs.foo }}"
```

```python
import os
with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
    f.write('foo=bar\n')
```

包含特殊字符可以使用 base64 先编码，过长的话建议用文件存储，jobs 间通过 artifacts 传递。

#### jobs 间传递数据

通过 outputs 传递：

```yaml
jobs:
  job1:
    runs-on: ubuntu-latest
    outputs:
      output1: ${{ steps.step1.outputs.foo }}
    steps:
      - id: step1
        run: echo "foo=bar" >> $GITHUB_OUTPUT
  job2:
    runs-on: ubuntu-latest
    needs: job1
    steps:
      - run: echo "${{ needs.job1.outputs.output1 }}"
```

通过 artifacts 传递：

```yaml
jobs:
  job1:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/upload-artifact@v4
        with:
          name: my-artifact
          path: ./site
  job2:
    runs-on: ubuntu-latest
    needs: job1
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: my-artifact
```

### 传递 secrets

敏感信息需要在 repo 的设置中添加 secrets，然后通过 `${{ secrets.SECRET_NAME }}` 使用。

在 Action 的输出中包含与 secret 内容相同的字符串会将其替换为 \*\*\*\*\*\* 处理。

### 权限控制

有时运行需要赋予 action 额外的权限，比如发布评论需要修改 PR，需要 `pull-requests: write` 权限。一种方法是为特定步骤设置环境变量 `GITHUB_TOKEN`，将其值设置为生成的个人 token（ghp_ 开头），但这种情况评论会以 token 的个人名义发布而非 action。

另一种更方便的方法是直接为 workflow 或单个 job 设置权限：

```yaml
permissions:
  contents: read          # 读取代码库内容
  pages: write      # 允许发布 GitHub Pages
  id-token: write   # 允许签发 OIDC token（pages 需要）
  pull-requests: write  # 允许修改 PR（发布评论需要）
```

更多权限见 [GitHub Actions docs > Reference > Workflow syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions)。

### 并发控制

可以通过并发控制来限制同一时间只能运行一个 workflow，或取消正在运行的旧 workflow：

```yaml
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }} # 以 workflow 名称和分支名作为组名
  cancel-in-progress: true # 只运行最新一次的部署，取消旧的没运行完的任务
```

同一个 group 内的 workflow 会互斥运行，只有最新一次会被执行，其他的会被取消。

## 常用 workflow 模板

### 构建并部署至 GitHub Pages

```yaml
name: Build and Deploy to GitHub Pages

on:
  push:
    branches:
      - master 
  workflow_dispatch:

permissions:
  contents: read
  pages: write      # 发布 pages 需要 pages: write
  id-token: write   # 发布 pages 需要 id-token: write

concurrency:
  group: 'deploy'
  cancel-in-progress: true # 只运行最新一次的部署，取消旧的没运行完的任务

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      - name: Setup GitHub Pages
        uses: actions/configure-pages@v5
      - name: Build site    # 其他构建命令
        run: ...
      - name: Upload artifact
        uses: actions/upload-pages-artifact@v3
        with:
          path: ./site      # build 产物目录

  deploy:
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    runs-on: ubuntu-latest
    needs: build
    steps:
      - name: Deploy to GitHub Pages
        id: deployment
        uses: actions/deploy-pages@v4
```

### 审计 PR 并发布评论

```yaml
name: Check PR

on:
  pull_request_target:  # 为了能在 PR 来自 fork 仓库时也能发布评论，需要 _target
    types: [opened, reopened, synchronize] # 创建、重新打开、更新时触发

permissions:
  contents: read
  pull-requests: write  # 发布 PR 评论需要 pull-requests: write

concurrency: ci-${{ github.workflow }}-${{ github.ref }}

jobs:
  check-pr:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:   # 需要 checkout 到 PR 所在的 repo 和 ref
          repository: ${{ github.event.pull_request.head.repo.full_name }}
          ref: ${{ github.event.pull_request.head.ref }}
      - name: Get changed files
        id: changed-files
        uses: tj-actions/changed-files@v46
      - name: Run checker
        if: steps.changed-files.outputs.any_changed == 'true' # 只在有改动时运行
        env:
          GITHUB_URL: ${{ github.event.pull_request.head.repo.clone_url }}
          GITHUB_REF: ${{ github.event.pull_request.head.ref }}
        run: ... # 运行检查脚本，便捷期间可以输出到文件 results.txt 方便评论
      - name: Comment PR
        if: steps.changed-files.outputs.any_changed == 'true'
        uses: thollander/actions-comment-pull-request@v3
        with:
          file-path: results.txt        # 从文件读取评论内容
          comment-tag: checker-results  # 用于标记评论，每次运行进行更新而非新发布
```

## 其他常用 actions

[:material-github: appleboy/scp-action](https://github.com/appleboy/scp-action)，用于通过 scp 上传文件到远程服务器：

```yaml
      - uses: appleboy/scp-action@v1
        with:
          host: ${{ secrets.HOST }}         # 通过 repo secrets 设置目标
          username: ${{ secrets.USERNAME }}
          password: ${{ secrets.PASSWORD }} # 或通过 key: 指定私钥
          port: ${{ secrets.PORT }}
          source: "site/*"
          target: ${{ secrets.SCP_TARGET }}
          strip_components: 1
```

[:material-github: tj-actions/changed-files](https://github.com/tj-actions/changed-files)，获取 push 或 PR 所更改的文件列表：

```yaml
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # fetch 完整历史记录，或至少为 2
      - name: Get changed files
        id: changed-files
        uses: tj-actions/changed-files@v46
        with:
          files: | # 可按 .gitignore 语法指定需要检查的文件
            ...
      - name: Do something if changed
        if: steps.changed-files.outputs.any_changed == 'true'
        env:    # 默认空格分割（可通过 separator 指定）
          CHANGED_FILES: ${{ steps.changed-files.outputs.all_changed_files }}
        run: ...
```
