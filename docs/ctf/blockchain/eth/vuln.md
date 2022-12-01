---
comment: True
counter: True
---

# 常见合约漏洞攻击手段

!!! abstract
    一些经典、常见的智能合约漏洞和攻击手段

## 整型溢出
uint 是 Solidity 中很常用的类型，但它是无符号整型，而且 solidity 0.8 之前没有溢出的检查，所以很容易造成溢出。

例如：[Ethernaut > Token](https://note.tonycrane.cc/writeups/ethernaut/#token)，题目中的 balances 记录是 mapping(address => uint)，而且在 transfer 函数中没有没有检查溢出：
```solidity
contract Token {
    mapping(address => uint) balances;
    uint public totalSupply;

    constructor(uint _initialSupply) public {
        balances[msg.sender] = totalSupply = _initialSupply;
    }

    function transfer(address _to, uint _value) public returns (bool) {
        require(balances[msg.sender] - _value >= 0);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        return true;
    }

    function balanceOf(address _owner) public view returns (uint balance) {
        return balances[_owner];
    }
}
```
这就导致了可以直接通过 transfer 比余额更多的 value，让记录的 balance 变成正的极大值。

这个问题的一个解决方法是判断溢出，可以使用 OpenZeppelin 的 [SafeMath](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/math/SafeMath.sol) 库：
```solidity 
import "@openzeppelin/contracts/utils/math/SafeMath.sol";

contract Token {
    using SafeMath for uint256;
    ...
}
```
其提供了一些方法用来进行带溢出检查的运算。

### 变长数组长度下溢任意写
整型溢出带来的一个更严重的问题是如果允许用户操作变长数组长度，则有可能导致数组长度下溢，从而可以读写全部的 storage。

例如：[Ethernaut > Alien Codex](https://note.tonycrane.cc/writeups/ethernaut/#alien-codex)，题目中提供了一个方法来减小数组长度，同时存在写入数组的函数：
```solidity
contract AlienCodex is Ownable {

    bool public contact;
    bytes32[] public codex;

    modifier contacted() {
        assert(contact);
        _;
    }

    function make_contact() public {
        contact = true;
    }

    function record(bytes32 _content) contacted public {
        codex.push(_content);
    }

    function retract() contacted public {
        codex.length--;
    }

    function revise(uint i, bytes32 _content) contacted public {
        codex[i] = _content;
    }
}
```
数组的长度是存在当前 slot 中的，是一个 uint256，所以可以从 0 减小到到 2**256-1，而且数组的真正存储位置是 keccak256(slot) 开头的，这样就可以通过计算来找到并读写任意 slot（计算 slot 也会用到溢出）。

## 重入攻击
重入攻击（Re-entrancy）是一个很经典的区块链智能合约攻击方式。

例如如下合约：
```solidity
contract Bank {
    mapping(address => uint256) balances;
    ...
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        msg.sender.call.value(amount)("");
        balances[msg.sender] -= amount;
    }
}
```
这个合约最大的问题在于它先转了钱，然后才更新的 balances。虽然转账不成功的话 revert 会回滚所有状态，但是它在转账的时候就会触发到接收合约的 fallback 函数。那么如果在 fallback 函数中继续调用 withdraw 函数，那么这次检查 require 的时候的 balances 仍是之前的值，也就是可以成功通过检查，继续下一条也就是转账，而在最后返回的时候才会一次次地减少 balances（也会下溢）。这时已经不用在意，因为钱已经一轮一轮地被转走了。

所以如果合约中有类似的操作的话，一定要先记账再转钱。或者可以使用 OpenZeppelin 的 [ReentrancyGuard](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/security/ReentrancyGuard.sol)，里面提供了一个 modifier nonReentrant 可以防止重入。

例题是：[Ethernaut > Re-entrancy](https://note.tonycrane.cc/writeups/ethernaut/#re-entrancy)。

## 伪随机数
由于区块链的特性，需要所有以太坊节点验证交易计算出相同结果达成共识，所以智能合约中并不能实现真随机数，而伪随机也有很多种可能来破解。

### 使用区块变量作为随机数
比如在验证的时候用到了当前区块的信息，如 coinbase、timestamp、number 等。而在我们进行交易时，是处在同一个区块的，所以可以同时计算出相同的随机数值。

例题：[Ethernaut > Coin Flip](https://note.tonycrane.cc/writeups/ethernaut/#coin-flip)、[Security Innovation > Lottery](https://note.tonycrane.cc/writeups/SecurityInnovation/#lottery)、[Security Innovation > Heads or Tails](https://note.tonycrane.cc/writeups/SecurityInnovation/#heads-or-tails)。

### 使用 blockhash 作为随机数
前面的几道例题中也有使用 blockhash 的情况，不过都是计算的当前区块的 hash。而这里要说的是另一种情况，也就是记录了某一时刻的 block number，然后在之后使用 blockhash 计算 hash。

这种情况的问题是，blockhash 函数只会计算最近 256 个块的 hash，更早的区块计算 blockhash 得到的都是 0。

例题：[Security Innovation > Raffle](https://note.tonycrane.cc/writeups/SecurityInnovation/#raffle)。

### 回滚攻击
比如预测和支付在同一次交易里，也就是说，我给出一个预测，对方就会通过交易的金额来给我反馈正确与否。这样的话合约转来的金额肯定是不一样的，那么在接收的时候就可以在 fallback 函数中判断一下接收到的金额，如果不是正确的金额，就可以直接 revert 来回滚整条交易，然后继续猜测。

## 薅羊毛攻击
比如一个 Token 合约，实现了空投函数，也就是发放一定数量的初始 token 给用户，但是限制了每个用户只能领取一次：
```solidity
contract Token is BasicToken {
    mapping (address => bool) airdroped;
    ...
    function airdrop() public {
        require(!airdroped[msg.sender]);
        airdroped[msg.sender] = true;
        balances[msg.sender] += 100;
    }
    ...
}
```
那么即使它限制了一个用户领一次，但是我们可以不断地创建新的合约来领取空投，因为每一个新合约都是一个新合约，然后再从合约中转出来汇总，拿到巨量 token。这就是所谓的薅羊毛攻击。

例题：[🔒 AAA > hard gambler](https://note.tonycrane.cc/writeups/AAA/#hard-gambler)

## 读取私有变量
这个漏洞就不必细说了，solidity 中的 private 变量只是没有公开查询的接口，实际上是可以直接读取对应 storage 的 slot 值来获取的。相关原理：[以太坊基础 > 存储](https://note.tonycrane.cc/ctf/blockchain/eth/basic/#_14)。

例题：[Ethernaut > Vault](https://note.tonycrane.cc/writeups/ethernaut/#vault)、[Ethernaut > Privacy](https://note.tonycrane.cc/writeups/ethernaut/#privacy)、[Security Innovation > Lock Box](https://note.tonycrane.cc/writeups/SecurityInnovation/#lock-box)。

## 远程调用
一个比较经典、不容易发现的漏洞，就是合约中大胆地使用了 delegatecall 来进行跨合约函数调用。以太坊提供的四种远程调用方法的区别在[以太坊虚拟机 > ETH 字节码 > 远程调用指令](https://note.tonycrane.cc/ctf/blockchain/eth/evm/#_9)中介绍过：

- call：执行环境为被调用者的环境，且 msg 会修改为调用者
- callcode：执行环境为调用者自己的环境，且 msg 会修改为调用者（一般不用）
- delegatecall：执行环境为被调用者的环境，且 msg 不会修改（也就相当于将其它合约的字节码拿到自己身上来执行）
- staticcall：不允许修改状态（这里不需要关心）

所以一个很显然的事情就是如果使用了 delegatecall 来调用外部给的合约地址中的函数，那么就完全有权限去修改这个合约中的状态。

例题：[Ethernaut > Preservation](https://note.tonycrane.cc/writeups/ethernaut/#preservation)：
```solidity
contract Preservation {
    address public timeZone1Library;
    address public timeZone2Library;
    address public owner; 
    uint storedTime;
    bytes4 constant setTimeSignature = bytes4(keccak256("setTime(uint256)"));

    constructor(address _timeZone1LibraryAddress, address _timeZone2LibraryAddress) public {
        timeZone1Library = _timeZone1LibraryAddress; 
        timeZone2Library = _timeZone2LibraryAddress; 
        owner = msg.sender;
    }

    function setFirstTime(uint _timeStamp) public {
        timeZone1Library.delegatecall(abi.encodePacked(setTimeSignature, _timeStamp));
    }

    function setSecondTime(uint _timeStamp) public {
        timeZone2Library.delegatecall(abi.encodePacked(setTimeSignature, _timeStamp));
    }
}

contract LibraryContract {
    uint storedTime;  

    function setTime(uint _time) public {
        storedTime = _time;
    }
}
```
虽然题目在 constructor 中就已经设定了 timeZoneLibrary，但是它是通过 delegatecall 调用的，而且其给出的 LibraryContract 中 slot 0 是 storedTime，setTime 函数会直接修改这个 slot。那么在调用 setFirstTime 时 delegatecall 修改掉了 slot 0，也就修改掉了 timeZone1Library。接着再 setFirstTime 就可以 delegatecall 我们自己输入的合约地址来修改 slot 2 也就是 owner 了。

[Ethernaut > Puzzle Wallet](https://note.tonycrane.cc/writeups/ethernaut/#puzzle-wallet) 同理，也是一道没有注意 delegatecall 导致 slot 混乱的例题。