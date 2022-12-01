---
comment: True
counter: True
---

# 其余重要 EIPs

!!! abstract
    除了 [ERC 标准](erc)中提到的 EIP 以外一些比较有用、需要注意的 EIP。

## EIP-2929
> Gas cost increases for state access opcodes

包含在柏林硬分叉当中，修改了几个和状态读取、地址访问、状态修改相关的字节码的 gas 消耗规则（降低受 DoS 攻击风险）。

在执行交易时，维护两个集合 `#!python accessed_addresses: Set[Address]`、 `#!python accessed_storage_keys: Set[Tuple[Address, Bytes32]]`，分别记录访问过的地址和访问过的存储键。

交易执行开始时初始化：

- accessed_addresses 包括 tx.sender、tx.to（或将要创建合约的地址）和其它预编译的地址
- accessed_storage_keys 为空

### 读取 storage
对于 CALL 系列、BALANCE 以及 EXT 系列字节码（原 gas 700）：

- 如果访问的目的地址不在 accessed_addresses 中，则
    - 消耗 COLD_ACCOUNT_ACCESS_COST = 2600 gas（冷读取）
    - 将地址添加到 accessed_addresses 中（预热）
- 如果访问的目的地址在其中，则：
    - 消耗 WARM_STORAGE_READ_COST = 100 gas（热读取）

对于 SLOAD（原 gas 800）：

- 如果 (address, storage_key) 对不在 accessed_storage_keys 中，则
    - 消耗 COLD_SLOAD_COST = 2100 gas
    - 将 (address, storage_key) 对添加到 accessed_storage_keys 中
    - *其中 address 表示要读取 storage 的合约地址，storage_key 表示要读取的 storage key（slot）
- 如果 (address, storage_key) 对在其中，则
    - 消耗 WARM_STORAGE_READ_COST = 100 gas

### 写入 storage
对于 SSTORE（原 gas 5000）：

- 如果 (address, storage_key) 对不在 accessed_storage_keys 中，则
    - 消耗 COLD_SSTORE_COST = 2100 gas
    - 将 (address, storage_key) 对添加到 accessed_storage_keys 中
    - 消耗 5000 - COLD_SSTORE_COST = 2900 gas 进行写入
    - *总计仍为 5000 gas
- 如果 (address, storage_key) 对在其中，则
    - 只消耗 5000 - COLD_SSTORE_COST = 2900 gas 进行写入

### selfdestruct
对于 SELFDESTRUCT（原 gas 5000）也有更改，因为其自毁转移余额时会访问其它地址，但规则和前面稍有不同：

- 如果接收者地址不在 accessed_addresses 中，则
    - 消耗 COLD_ACCOUNT_ACCESS_COST = 2600 gas
    - 将地址添加到 accessed_addresses 中
    - 消耗 5000 gas 进行自毁
- 如果接收者地址在其中，则
    - 只消耗 5000 gas 进行自毁
    - ***不**会再消耗 WARM_STORAGE_READ_COST = 100 gas

### 用例
hackergame2022 的链上预言家第三问要使用这一特性，因为它需要在不修改状态的情况下在一次交易中记下一个值并输出：

??? question "题目合约"
    ```solidity
    pragma solidity =0.8.17;

    interface MemoryMaster {
        function memorize(uint256 n) external view;
        function recall() external view returns (uint256);
    }

    contract Challenge {
        function test(MemoryMaster m, uint256 n) external returns (bool) {
            m.memorize(n);
            uint256 recalled = m.recall();
            return recalled == n;
        }
    }
    ```

解法就是利用插槽冷热读取 gas 消耗的较大差异，来逐位记录：

??? success "exp"
    ```solidity
    contract Exploit {
        function memorize(uint256 n) external view {
            for (uint i = 0; i < 256; ++i) {
                if ((n >> i) & 1 == 1) check(1218+i); // 第一次 check，是冷的
            }
        }
        function recall() external view returns (uint256) {
            uint256 res;
            for (uint i = 0; i < 256; ++i) {
                if (check(1218+i)) res |= 1 << i; // 如果前面 check 过了，就是热的，gas 消耗少于 1k，会返回 true
            }
            return res;
        }
        function check(uint256 x) internal view returns (bool) {
            uint gas = gasleft();
            uint b = address(uint160(x)).balance; // 利用 BALANCE 字节码
            return gas - gasleft() < 1000;
        }
    }
    ```