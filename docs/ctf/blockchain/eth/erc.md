---
comment: True
counter: True
---

# ERC 标准

!!! abstract
    分析、记录一些常用的 ERC 标准

## EIP 与 ERC
EIP（Ethereum Improvement Proposals，以太坊改进提案）是开发者改进以太坊平台的提案列表（类似 python 的 pep），包含了很多方面的内容，有核心协议、客户端 API、合约标准等…… 可以在 [eips.ethereum.org](https://eips.ethereum.org/) 找到全部的 EIP 列表。

其中与标准有关的称为 [ERC](https://eips.ethereum.org/erc)（Ethereum Request for Comment），其中有很多实用的标准。而且 OpenZeppelin 也实现了其中的一些合约标准 [:material-github: OpenZeppelin/openzeppelin-contracts](https://github.com/OpenZeppelin/openzeppelin-contracts)

下面来分别看一下其中几个经典常用的 ERC

## ERC-20
ERC-20 规定了一个代币（token）标准，提供了一系列基础的方法，包括转移代币、授权等。

### 标准
- **name**：token 名称（可选项）
    ```solidity
    function name() public view returns (string)
    ```
- **symbol**：token 符号（可选项）
    ```solidity
    function symbol() public view returns (string)
    ```
- **decimals**：token 精度（可选项）
    ```solidity
    function decimals() public view returns (uint8)
    ```
    - 例如，decimals 为 2，表示当前一个 token 可以被分成 100 份
    - 查询余额时返回的是最小精度，也就是说，mint 了 1 token 之后，查询到的是 100
    - 类比 ETH，其 decimals 是 18，也就是 1 ether 和 1 wei 的关系

以上可选项都是为了易用性而增加的，不必须提供，而且其它合约不能默认该 ERC-20 token 有这些函数。以下是标准要求必须提供的函数：

- **totalSupply**：发行的 token 总量
    ```solidity
    function totalSupply() public view returns (uint256)
    ```
    - 可以通过 `#!solidity uint256 public totalSupply;` 来实现
- **balanceOf**：某个地址上拥有的 token 数量
    ```solidity
    function balanceOf(address _owner) public view returns (uint256 balance)
    ```
    - 可以通过 `#!solidity mapping (address => uint256) public balanceOf;` 来实现
- **transfer**：转移 token
    ```solidity
    function transfer(address _to, uint256 _value) public returns (bool success)
    ```
    - 从 msg.sender 转移 _value 个 token 到 _to
    - 会触发 `Transfer` 事件（即使 _value 为 0）
- **transferFrom**：从某个地址转移 token
    ```solidity
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success)
    ```
    - 从 _from 转移 _value 个 token 到 _to
    - 会触发 `Transfer` 事件（即使 _value 为 0）
    - 用于代理转移，需要 _from 先授权 msg.sender 转移 token
- **approve**：授权某个地址代理转移 token
    ```solidity
    function approve(address _spender, uint256 _value) public returns (bool success)
    ```
    - 授权 _spender 最多转移 _value 个 token
    - 会触发 `Approval` 事件（即使 _value 为 0）
- **allowance**：查询某个地址可以代理转移的 token 数量
    ```solidity
    function allowance(address _owner, address _spender) public view returns (uint256 remaining)
    ```

一些会触发的事件：

- **Transfer**：token 转移
    ```solidity
    event Transfer(address indexed _from, address indexed _to, uint256 _value)
    ```
- **Approval**：授权
    ```solidity
    event Approval(address indexed _owner, address indexed _spender, uint256 _value)
    ```

完整的接口：
```solidity
interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address who) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
    function transfer(address to, uint256 value) external returns (bool);
    function approve(address spender, uint256 value) external returns (bool);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
}
```

### 实现
OpenZeppelin 的实现：[ERC20.sol](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/ERC20.sol)
```solidity
import "@openzeppelin/contracts/token/ERC20/ERC20.sol"
```

#### 扩展
OpenZeppelin 还实现了一系列扩展的合约：[ERC20/extensions](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/extensions)

- ERC20Burnable
    - 实现了 burn、burnFrom 函数，用于销毁 token
- ERC20Capped
    - 实现了 cap 函数，用于限制 token 总量
- ERC20FlashMint
    - 实现了 ERC-3156 的闪电贷接口
- ...

## ERC-721
ERC-721 是一个 NFT（非同质化代币）标准。

TODO


## ERC-777


## ERC-1155


## ERC-3156


## ERC-173


## ERC-55