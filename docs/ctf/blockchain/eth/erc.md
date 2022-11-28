---
comment: True
counter: True
---

# ERC 标准

!!! abstract
    分析、记录一些常用的 ERC 标准

## EIP 与 ERC
EIP（Ethereum Improvement Proposals，以太坊改进提案）是开发者改进以太坊平台的提案列表（类似 python 的 pep），包含了很多方面的内容，有核心协议、客户端 API、合约标准等…… 可以在 [eips.ethereum.org](https://eips.ethereum.org/) 找到全部的 EIP 列表。

其中与合约标准有关的称为 [ERC](https://eips.ethereum.org/erc)（Ethereum Request for Comment），其中有很多实用的标准。而且 OpenZeppelin 也实现了其中的一些 [:material-github: OpenZeppelin/openzeppelin-contracts](https://github.com/OpenZeppelin/openzeppelin-contracts)

下面来分别看一下其中几个经典常用的 ERC

## ERC-20

ERC-20 规定了一个代币（token）标准，提供了一系列基础的方法，包括转移代币、授权等。