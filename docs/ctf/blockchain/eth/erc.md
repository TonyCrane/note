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
ERC-721 是一个 NFT（Non-Fungible Token，非同质化代币）标准。“非同质化” 指的是，相对于 ERC-20 的 token 一种代币可以发行很多个，而 NFT 一种代币只能发行一个给一个地址。

ERC-721 规范规定了这样一种代币规范，支持发行多种 NFT，每个 NFT 有一个标识符，即 tokenId，每个 NFT 只能属于一个地址。且可以进行 NFT 的转移、授权、查询。

不同于 ERC-20，它的授权机制有两种方案：

- 一个账户将它所拥有的一个 NFT 授权给另一个账户来操作（一个 NFT 只能授权给一个账户）
- 一个账户授权另一个账户来对其拥有的全部 NFT 进行操作

### 标准接口
#### 转移
- **safeTransferFrom**：安全地转移 NFT
    ```solidity
    function safeTransferFrom(address _from, address _to, uint256 _tokenId, bytes _data) external payable
    ```
    - 将 _from 拥有的 _tokenId 标识的 NFT 转移给 _to
    - 如果 _to 是一个合约地址，会调用其 `onERC721Received` 函数，检查返回值是否是这个函数的 selector
        ```solidity
        function onERC721Received(address _operator, address _from, uint256 _tokenId, bytes _data) external returns(bytes4)
        ```
        - 实现时可以返回 `bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"))`
        - 也可以返回 this.onERC721Received.selector
    - msg.sender 只允许是当前要转移的 NFT 的所有者、所有者的授权操作者、所有者授权操作这枚 NFT 的操作者
    - _to 不能是 0 地址
    - 会触发 `Transfer` 事件
- **safeTransferFrom**
    ```solidity
    function safeTransferFrom(address _from, address _to, uint256 _tokenId) external payable
    ```
    - 与上面的函数一样，只是不需要传入 _data（为 ""）
- **transferFrom**：转移 NFT
    ```solidity
    function transferFrom(address _from, address _to, uint256 _tokenId) external payable
    ```
    - 与上面的转移函数类似，不过不检查 _to 是合约时是否正确实现了 `onERC721Received` 函数

#### 授权
- **approve**：授权操作者操作单个 NFT
    ```solidity
    function approve(address _approved, uint256 _tokenId) external payable
    ```
    - 将 _tokenId 标识的 NFT 授权给 _approved 操作
    - msg.sender 只允许是当前要转移的 NFT 的所有者、所有者的授权操作者
    - 一个 NFT 只能拥有一个授权操作者
    - 会触发 `Approval` 事件
- **setApprovalForAll**：授权/取消授权操作者操作拥有的所有 NFT
    ```solidity
    function setApprovalForAll(address _operator, bool _approved) external
    ```
    - 将 _operator 授权/取消授权操作所有 NFT
    - msg.sender 只允许是当前要转移的 NFT 的所有者、所有者的授权操作者
    - 会触发 `ApprovalForAll` 事件


#### 查询
- **ownerOf**：查询一个 NFT 的拥有者
    ```solidity
    function ownerOf(uint256 _tokenId) external view returns (address)
    ```
- **balanceOf**：查询某个地址拥有的 NFT 数量
    ```solidity
    function balanceOf(address _owner) external view returns (uint256)
    ```
- **getApproved**：查询某个 NFT 的授权操作者
    ```solidity
    function getApproved(uint256 _tokenId) external view returns (address)
    ```
- **isApprovedForAll**：查询某个地址是否被授权操作某个账户的所有 NFT
    ```solidity
    function isApprovedForAll(address _owner, address _operator) external view returns (bool)
    ```

#### 事件
- **Transfer**：转移 NFT 时触发
    ```solidity
    event Transfer(address indexed _from, address indexed _to, uint256 indexed _tokenId)
    ```
- **Approval**：授权操作者操作单个 NFT 时触发
    ```solidity
    event Approval(address indexed _owner, address indexed _approved, uint256 indexed _tokenId)
    ```
- **ApprovalForAll**：授权/取消授权操作者操作拥有的所有 NFT 时触发
    ```solidity
    event ApprovalForAll(address indexed _owner, address indexed _operator, bool _approved)
    ```

### 扩展
#### 元数据扩展
- **name**：查询当前合约发行的一系列 NFT 的名称
    ```solidity
    function name() external view returns (string)
    ```
- **symbol**：查询当前合约发行的一系列 NFT 的符号
    ```solidity
    function symbol() external view returns (string)
    ```
- **tokenURI**：查询某个 NFT 的元数据
    ```solidity
    function tokenURI(uint256 _tokenId) external view returns (string)
    ```
    - 返回的是一个 URI，指向一个 JSON 文件，其包含了元数据

#### 枚举扩展
- **totalSupply**：查询发行的 NFT 总数
    ```solidity
    function totalSupply() external view returns (uint256)
    ```
- **tokenByIndex**：根据索引查询 NFT
    ```solidity
    function tokenByIndex(uint256 _index) external view returns (uint256)
    ```
    - _index < totalSupply()
- **tokenOfOwnerByIndex**：根据索引查询某个地址拥有的 NFT
    ```solidity
    function tokenOfOwnerByIndex(address _owner, uint256 _index) external view returns (uint256)
    ```
    - _index < balanceOf(_owner)

### 实现
OpenZeppelin 的实现：[ERC721.sol](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC721/ERC721.sol)

```solidity
import "@openzeppelin/contracts/token/ERC721/ERC721.sol"
```

而且也实现了一些扩展。

它实现中的一些记录用的 mapping，可以看出整体结构：
```solidity
// Mapping from token ID to owner address
mapping(uint256 => address) private _owners;

// Mapping owner address to token count
mapping(address => uint256) private _balances;

// Mapping from token ID to approved address
mapping(uint256 => address) private _tokenApprovals;

// Mapping from owner to operator approvals
mapping(address => mapping(address => bool)) private _operatorApprovals;
```

## ERC-3156
ERC-3156 提供了一套闪电贷标准，分为两部分，lender（给钱的人），borrower（借钱的人）。

### Lender
Lender 需要实现三个接口

- **maxFlashLoan**：查询最大可贷额度
    ```solidity
    function maxFlashLoan(address token) external view returns (uint256);
    ```
    - token 是要贷的币种合约地址
    - 返回值是最大可贷额度
    - 不可以贷款时返回 0，不能 revert
- **flashFee**：查询贷款手续费
    ```solidity
    function flashFee(address token, uint256 amount) external view returns (uint256);
    ```
    - 贷 amount 个 token 的手续费
    - 不可以贷款时必须 revert
- **flashLoan**：执行闪电贷
    ```solidity
    function flashLoan(
        IERC3156FlashBorrower receiver,
        address token,
        uint256 amount,
        bytes calldata data
    ) external returns (bool);
    ```
    - receiver 是借款人，必须实现 IERC3156FlashBorrower 接口
    - flashLoan 中一定要调用 receiver 的 onFlashLoan 方法，且验证返回值：
        ```solidity
        ...
        require(receiver.onFlashLoan(msg.sender, token, amount, fee, data) == CALLBACK_SUCCESS, "ERC3156: Callback failed");
        ...
        ```
        - 其中 CALLBACK_SUCCESS 为 keccak256("ERC3156FlashBorrower.onFlashLoan")
    - 在调用 onFlashLoan 之前，必须先转移 amount 个 token 给 receiver
    - 在调用 onFlashLoan 时，不能修改传入的数据，第一个参数必须是 msg.sender
    - 在调用 onFlashLoan 之后，必须从 receiver 转移 amount + fee 个 token 回来到自己身上，如果不成功，则 revert
    - 成功后返回 true

### Borrower
Borrower 需要实现一个接口，onFlashLoan，在收到闪电贷后，会执行这个函数，执行后会被 lender 取回贷款和手续费。这些都在一个交易中结束，也就是说，只有 onFlashLoan 中是得到了贷款的。

- **onFlashLoan**：收到闪电贷后 callback
    ```solidity
    function onFlashLoan(
        address initiator,
        address token,
        uint256 amount,
        uint256 fee,
        bytes calldata data
    ) external returns (bytes32);
    ```
    - initiator 是申请闪电贷的地址
    - data 是 initiator 传入的额外信息，可以进行编解码
    - 返回之前一定要确保 approve 够了 amount + fee 个 token 给 lender 用来取回
    - 必须返回 keccak256("ERC3156FlashBorrower.onFlashLoan")

### 闪电贷流程
![](/assets/images/ctf/blockchain/eth/erc/img1_light.png#only-light)
![](/assets/images/ctf/blockchain/eth/erc/img1_dark.png#only-dark)

### 实现
[EIP-3156](https://eips.ethereum.org/EIPS/eip-3156) 中就实现了 Lender 和 Borrower 作为示例。同时也实现了 Flash Mint（闪电铸）合约作为例子。

## ERC-173
ERC-173 提供了所有权相关的标准，接口很简单：

- **owner**：查询所有者
    ```solidity
    function owner() external view returns (address);
    ```
    - 当前合约的所有者
- **transferOwnership**：转移所有权
    ```solidity
    function transferOwnership(address newOwner) external;
    ```
    - 会触发 OwnershipTransferred 事件
- **OwnershipTransferred**：所有权转移事件
    ```solidity
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    ```

### 实现
OpenZeppelin 实现了一个 [Ownable.sol](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/access/Ownable.sol)，其包含了这些接口，以及一些额外的功能：

- **onlyOwner**：修改器，限制当前函数只有所有者能调用
    ```solidity
    modifier onlyOwner() {
        require(owner() == _msgSender(), "Ownable: caller is not the owner");
        _;
    }
    ```
- **renounceOwnership**：放弃所有权
    ```solidity
    function renounceOwnership() public virtual onlyOwner {
        emit OwnershipTransferred(_owner, address(0));
        _owner = address(0);
    }
    ```
    - 即将所有权转移给 0 地址

## ERC-55
ERC-55 是一个地址校验标准，利用字母的大小写来进行校验，检查地址有没有被无意打错。

生成带校验的地址的方法是：

- 将地址当作 16 进制数
- 计算地址的 keccak256 哈希值
- 处理地址的每一位 i
    - 如果第 i 位上为数字，则直接保留
    - 检查哈希值的第 4*i 位是否为 1，如果是 1 则大写，否则小写

```javascript
const createKeccakHash = require('keccak')

function toChecksumAddress (address) {
  address = address.toLowerCase().replace('0x', '')
  var hash = createKeccakHash('keccak256').update(address).digest('hex')
  var ret = '0x'

  for (var i = 0; i < address.length; i++) {
    if (parseInt(hash[i], 16) >= 8) {
      ret += address[i].toUpperCase()
    } else {
      ret += address[i]
    }
  }

  return ret
}
```