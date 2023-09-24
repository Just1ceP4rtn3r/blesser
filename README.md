# Blesser: A Stateful Fuzzer Tool

Blesser is a stateful fuzzer tool designed to help developers and security researchers find vulnerabilities in software applications. It is based on a state machine model that allows for intelligent fuzzing of input data, making it an effective and efficient tool for finding bugs.

## Project Overview



![](Figures/Architecture.svg)

## Installation and Usage

### Requirements

-   Python 3.x

### Installation

```bash
$ sudo apt-get install python-pip libglib2.0-dev
```


To install Blesser, follow these steps:

1.  Clone the Blesser repository from GitHub:

```
bashCopy code
git clone https://github.com/yourusername/blesser.git
```

1.  Navigate to the `blesser` directory:

```
bashCopy code
cd blesser
```

1.  Install the required Python packages:

```
Copy code
pip install -r requirements.txt
```

### Usage

To use Blesser, follow these steps:

1.  Run the `blesser.py` script:

```
phpCopy code
python blesser.py <options>
```

1.  Blesser will start running and will automatically generate input data based on the current state of the state machine.
2.  To stop Blesser, press `CTRL+C`.


## TODO


### Challenges

- [ ] EQ如果找到了反例，是否需要优化（例如证明反例的新状态是否与假设模型中的某个状态一致）
- [ ] 有没有意义做Peripheral对Central进行Fuzzing测试
- [ ] Out Of Bound (OOB)这种连接如何自动化
- [ ] 优化方式：如果前面的状态中协商了等级A的能力，后续变异增加使用其他等级能力的概率
- [ ] random的值，是否需要进行重放的变异








