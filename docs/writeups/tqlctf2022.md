---
comment: True
---

# TQLCTF 2022 Writeup

!!! abstract
    清华主办的比赛，misc 基本都是 NanoApe 出的，质量高的很

    - [nano 的官方 writeup](https://nano.ac/posts/79c74adf)

---

## Ranma½
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)

打开 flag 十六进制，是一个非标准的 UTF-8 编码，也就是部分可以一个字节表示一个字符的，写成了符合 UTF-8 编码原理的两个字节，导致编辑器无法正常读取（但是 vim 能读取）

可以得到一串密文：

> KGR/QRI 10646-1 zswtqgg d tnxcs tsdtofbrx osk ndnzhl gna Ietygfviy Idoilfvsu Arz (QQJ) hkkqk maikaglvusv ubyp cw ekg krzyj'o kitwkbj alypsdd.  Wjs rzvmebrwoa duwcuosu pqecgqamo cw ekg IFA, uussmpu, ysum aup qfxschljyk swks pcbb khxnsee drdoqpgpwfyv cbg xeupctzou, oql gneg ylv nsg bb zds upygzrxzkjh fq XVT-8, wpr uxxvnw qt wpvy isdz. XVT-8 kif zds tsdtofbrxegktf qt szryafmtqi hkm sahz LD-DUQLQ egjuv, auqjllvtc qfxschljvrehp hlvv iqyk omjehog, sieyafj lqf cwprx ocwezcfh bugp fvwb qb XA-NYYWZ gdniha oap oip wtoqacgnsee wq cwprx rocfhu. HTTPZB{QFOLP6_KRZ1Q}

很容易猜测开头应该是 ISO/IEC 10646-1，而能将 I 加密为不同字符，想到维吉尼亚密码

查到原文是 RFC 3629 的 abstract:

> ISO/IEC 10646-1 defines a large character set called the Universal Character Set (UCS) which encompasses most of the world's writing systems.  The originally proposed encodings of the UCS, however, were not compatible with many current applications and protocols, and this has led to the development of UTF-8, the object of this memo.  UTF-8 has the characteristic of preserving the full US-ASCII range, providing compatibility with file systems, parsers and other software that rely on US-ASCII values but are transparent to other values.

反推出 key：`CODINGWORLD`<br/>
解密得到结尾的 flag：`TQLCTF{CODIN6_WOR1D}`

---

## wordle
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)

wordle 游戏，要求 512 局全部猜对

先写了一个 solver，改写的 [:material-github: zulkarnine/WordleSolver](https://github.com/zulkarnine/WordleSolver)<br/>
easy 和 normal 难度均没有 flag 相关信息，所以要解出 insane 难度，即 512 局全部控制在 4 次以内猜出来，不现实，找其它方法

发现每局都会先给出一个 hex 值，而且算法已知，并且由题目文件中注释 `# To prevent the disclosure of answer` 知道反推答案不现实<br/>
再考虑到整个题目是在一个 while True 以内的，解出一个难度后不会关掉题目，而是可以继续选择难度继续解题

所以存在爆破 random 模块伪随机数的可能<br/>
因为 hex 值算法已知：

```python
id = random.randrange(len(valid_words) * (2 ** 20))
answer = valid_words[id % len(valid_words)]
id = (id // len(valid_words)) ^ (id % len(valid_words))
return hex(id)[2:].zfill(5), answer
```

如果知道答案则相当于知道 `id % len(valid_words)`，再与 hex 值异或可以得到 `id // len(valid_words)`，而 `len(valid_words)` 已知，所以可以直接推得 `id`，即 randrange 的结果

爆破 random 使用 [:material-github: tna0y/Python-random-module-cracker](https://github.com/tna0y/Python-random-module-cracker)，需要 512 个 random 的结果

进行两轮 easy 难度（使用 solver）就可以得到连续 512 个伪随机数，但是存在爆破出错的可能，第二轮的后 400 个可以用来验证<br/>
如果后 400 个完全预测正确，就可以进行 insane 难度，直接预测随机数计算得到答案

??? done "完整代码"
    ```python
    import re
    import sys
    from pwn import *
    from tqdm import tqdm
    from enum import Enum
    from collections import Counter
    from randcrack import RandCrack

    MAX_ATTEMPT = 6

    class LetterVerdict(Enum):
        GREEN = 1
        YELLOW = 2
        GRAY = 3

    class AttemptVerdict(Enum):
        WON = 1
        LOST = 2
        FAILED_ATTEMPT = 3
        INVALID_TRY = 4
        INVALID_WORD = 5

    def get_all_wordle_words():
        with open("valid_words.txt", "r") as infile:
            return [line.strip() for line in infile.readlines()]

    class WordleSolver:
        def __init__(self):
            self.__all_possible_words = set(get_all_wordle_words())
            self.__invalid_letters = set()
            self.__untried_letters = set()
            self.__candidate_words = []
            self.__green_blocks = set()
            self.__yellow_blocks = set()
            self.attempt = 0
            self.game_number = -1
            self.tries = []
            self.reset()

        def reset(self):
            self.__invalid_letters.clear()
            self.__candidate_words = sorted(list(self.__all_possible_words))
            self.__yellow_blocks.clear()
            self.__green_blocks.clear()
            self.attempt = 0
            self.__untried_letters = set(chr(ord('a') + i) for i in range(26))
            self.game_number += 1
            self.tries.clear()

        def __contains_forbidden_letters(self, word):
            for ind, c in enumerate(word):
                if (c, ind) not in self.__green_blocks: # here fix a bug in
                    if c in self.__invalid_letters:     # the original solver
                        return True
            return False

        def __get_untried_letter_probability(self, words):
            counter = Counter()
            for w in words:
                for c in w:
                    if c in self.__untried_letters:
                        counter[c] += 1
            return counter

        def __get_letter_freq_map(self, words):
            counter = Counter()
            for w in words:
                for c in w:
                    counter[c] += 1
            return counter

        def __matches_green_constraints(self, word):
            for letter, index in self.__green_blocks:
                if word[index] != letter:
                    return False
            return True

        def __matches_yellow_constraints(self, word):
            for letter, index in self.__yellow_blocks:
                if word[index] == letter or letter not in word:
                    return False
            return True

        def __filter_out_invalid_words(self):
            new_candidates = []
            for word in self.__candidate_words:
                if self.__contains_forbidden_letters(word) or not self.__matches_green_constraints(
                        word) or not self.__matches_yellow_constraints(word):
                    continue
                new_candidates.append(word)

            self.__candidate_words = new_candidates

        def __make_educated_guess(self):
            untried_letters = self.__get_untried_letter_probability(self.__candidate_words)
            freq_map = self.__get_letter_freq_map(self.__candidate_words)
            if len(untried_letters) > 1 and self.attempt <= MAX_ATTEMPT - 1:
                word_with_score = []
                word_list = self.__all_possible_words
                for word in word_list:
                    letters = set(word)
                    untried_score = sum(untried_letters[c] if c in untried_letters else 0 for c in letters)
                    freq_score = sum(freq_map[c] for c in letters)
                    word_with_score.append((word, untried_score, freq_score))
                ranked_words = sorted(word_with_score,
                                      key=lambda item: (-item[1], -item[2], item[0]))
                guess = ranked_words[0][0]
            else:
                guess = sorted(
                    self.__candidate_words,
                    key=lambda word: (-len(set(word)), -sum(freq_map[c] for c in word), word)
                )[0]
            return guess

        def __pick_a_word(self):
            self.__filter_out_invalid_words()
            if len(self.__candidate_words) == 0: # for debug
                res = input(">>> ")
                return res.strip()
            elif len(self.__candidate_words) == 1:
                return self.__candidate_words[0]
            return self.__make_educated_guess()

        def solve(self, wordle):
            last_guess = ""
            wordle.p.recvuntil(b"#")
            hex_id = wordle.p.recvline().decode("utf-8").strip()
            while True:
                self.attempt += 1
                guess = self.__pick_a_word()
                if last_guess == guess:  # here fix a bug in the original solver
                    self.__candidate_words.remove(guess)
                    guess = self.__pick_a_word()
                result, letter_verdicts = wordle.guess(guess)
                last_guess = guess
                self.tries.append(guess)
                if result == AttemptVerdict.WON:
                    return hex_id, guess
                elif result == AttemptVerdict.LOST:
                    return False
                elif result == AttemptVerdict.FAILED_ATTEMPT:
                    for chr in guess:
                        self.__untried_letters.discard(chr)
                    for i in range(len(letter_verdicts)):
                        letter, verdict = letter_verdicts[i]
                        if verdict == LetterVerdict.GRAY:
                            flag = True
                            for (l, _) in self.__yellow_blocks: # here fix a bug in
                                if l == letter:                 # the original solver
                                    flag = False
                                    break
                            if flag:
                                self.__invalid_letters.add(letter)
                        elif verdict == LetterVerdict.GREEN:
                            self.__green_blocks.add((letter, i))
                            if (letter, i) in self.__yellow_blocks:
                                self.__yellow_blocks.remove((letter, i))
                        elif verdict == LetterVerdict.YELLOW:
                            self.__yellow_blocks.add((letter, i))
                        else:
                            exit(1)
                elif result == AttemptVerdict.INVALID_WORD:
                    self.attempt -= 1
                    self.__candidate_words.remove(guess)
                    self.__all_possible_words.remove(guess)

    class Wordle:
        def __init__(self, mode):
            self.p = connect("47.106.102.129", 23370)
            self.p.sendlineafter(b"> ", str(mode).encode("utf-8"))

        def restart(self, mode):
            self.p.sendlineafter(b"> ", str(mode).encode("utf-8"))

        def guess(self, word):
            self.p.sendlineafter(b"> ", word.encode("utf-8"))
            status = self.p.recvuntil(b"!")
            if status == b"Correct!":
                return AttemptVerdict.WON, None
            result = self.p.recvline().decode("utf-8")
            res = re.findall(r"\[4(\d)m", result)
            ret = []
            for i in range(5):
                c = word[i]
                if res[i] == "7":
                    ret.append((c, LetterVerdict.GRAY))
                elif res[i] == "3":
                    ret.append((c, LetterVerdict.YELLOW))
                else:
                    ret.append((c, LetterVerdict.GREEN))
            attempt_verdict = AttemptVerdict.WON
            for _, verdict in ret:
                if verdict != LetterVerdict.GREEN:
                    attempt_verdict = AttemptVerdict.FAILED_ATTEMPT
                    break
            return attempt_verdict, ret

    cracker = RandCrack()
    wordle = Wordle(0)
    solver = WordleSolver()

    def calc_random_id(hex_id, word):
        valid_words = get_all_wordle_words()
        length = len(valid_words)
        index = valid_words.index(word)  # id % len(valid_words)
        Id = eval("0x"+hex_id)
        tmp = Id ^ index # id // len(valid_words)
        return tmp * length + index

    def calc_hex_id_and_word(random_value):
        valid_words = get_all_wordle_words()
        length = len(valid_words)
        word = valid_words[random_value % length]
        hex_value = (random_value // length) ^ (random_value % length)
        return hex(hex_value)[2:].zfill(5), word

    with tqdm(total=624, desc="Cracking random...") as pbar:
        for i in range(512):
            solver.reset()
            hex_id, answer = solver.solve(wordle)
            random_value = calc_random_id(hex_id, answer)
            cracker.submit(random_value)
            pbar.update(1)
        wordle.restart(0)
        for i in range(112):
            solver.reset()
            hex_id, answer = solver.solve(wordle)
            random_value = calc_random_id(hex_id, answer)
            cracker.submit(random_value)
            pbar.update(1)
    with tqdm(total=400, desc="Verifying crack result...") as pbar:
        for i in range(400):
            solver.reset()
            predict = cracker.predict_randrange(4090 * (2**20))
            p_hex_id, p_answer = calc_hex_id_and_word(predict)
            hex_id, answer = solver.solve(wordle)
            if p_hex_id != hex_id:
                print(f"Crack faild:\n  predict: {p_hex_id}, {p_answer}\n  challenge: {hex_id}, {answer}")
                sys.exit(1)
            pbar.update(1)

    wordle.p.sendlineafter(b"> ", b"3") # insane level
    with tqdm(total=512, desc="Solving insane level...") as pbar:
        for i in range(512):
            wordle.p.recvuntil(b"#")
            hex_id = wordle.p.recvline().decode("utf-8").strip()
            predict = cracker.predict_randrange(4090 * (2**20))
            p_hex_id, p_answer = calc_hex_id_and_word(predict)
            if hex_id != p_hex_id:
                print(f"Predict failed:\n  predic: {p_hex_id}\n  challenge: {hex_id}")
                sys.exit(1)
            wordle.p.sendlineafter(b"> ", p_answer.encode("utf-8"))
            pbar.update(1)

    wordle.p.interactive()
    ```

---


## the Ohio State University
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)

题目提供了 .osz 文件，是 osu! 游戏谱面的压缩文件，可以通过游戏直接打开，或者解压获得素材文件<br/>
在osu官网搜索到对应的谱面并下载：https://osu.ppy.sh/beatmapsets/1235288#mania/2568956

将两份谱面解压，比较文件不同

背景图片的 exif 里有一项属性：`pwd: VVelcome!!`<br/>
推测图片会有带密码的隐藏内容，steghide 解密得到 flag 开头：`TQLCTF{VVElcOM3`

BASIC 难度谱面文件有一行差异：`WAVPassword: MisoilePunch`<br/>
暗示了 wav 音频文件会有隐藏内容，使用 SilentEye 即可提取<br/>
拿到 flag 中间部分`_TO_O$u_i7s_`

最后还剩下 VIVID 难度谱面，比对发现谱面尾杀被改了

剩下一部分是 flag 的结尾，所以结尾应该是 }，其对应16进制值为 7D，二进制 0111 1101，发现结尾确实有类似 0111 1101 的 note<br/>
然后记录所有 note，转换为字符就可以拿到最后一部分flag：5HoWtIme}

拼接得到完整flag：TQLCTF{VVElcOM3_TO_O$u_i7s_5HoWtIme}

---

## Nanomaze
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)

是 nano 复刻的 revomaze green 迷宫

主要玩法就是整个地图在左右方向上是循环的（地图卷成一个圆筒）<br/>
整个迷宫地图包含高度，每次只能向同高度走，高度下降了就会收到 [click] 提示，这之后也就不能再原路返回了<br/>
并且有特殊位置可以使高度上升（第一行某处）<br/>
目标是到达地图的最下面一层的某个位置

由于左右循环，所以先找到地图的横向大小<br/>
可以发现向右走一段后会走不动，而向左走可以不断得到 click，通过两个 click 之间的坐标差可以得到地图的横向大小约 75<br/>
所以之后的横向坐标就可以对 75 取模

同时也可以发现每次向右走到走不动的距离不一定<br/>
这说明起始位置并不固定，所以需要先移动到不能动，再重置坐标，这样会清楚很多

然后就是盲着走迷宫，用了 pygame 来绘制到达的点，以及发生 click 的位置
??? done "代码"
    ```python
    from pwn import *

    import pygame
    from pygame.locals import *

    p = process(["python", "main.py"]) # 本地复现
    X, Y = 0, 0
    width = 75

    pygame.init()
    WHITE = (255, 255, 255)
    GREEN = (0, 255, 0)
    RED = (255, 0, 0)
    BLUE = (0, 0, 255)

    size = width, height = 800, 1000
    clock = pygame.time.Clock()
    screen = pygame.display.set_mode(size)
    pygame.display.set_caption("nanomaze")
    screen.fill(WHITE)
    pygame.display.flip()

    def send(direction):
        res = p.recvuntil(b"> ")
        click = False
        if "[click]" in res.decode("utf-8"):
            click = True
        p.sendline(direction.encode("utf-8"))
        return click, p.recvline().decode("utf-8").strip()

    def update_value(direction, value):
        global X, Y
        if direction == "w":
            X -= value
        elif direction == "a":
            Y -= value
        elif direction == "s":
            X += value
        else:
            Y += value
        if Y < 0:
            Y += 75

    def move(direction, aim=None):
        if aim is None:
            times = 0
            while times < 20:
                click, res = send(direction)
                if click:
                    log.info(f"click at    ({X}, {Y})")
                    return
                if "Cannot be moved" in res:
                    times += 1
                else:
                    update_value(direction, float(res.split()[2]))
                    times = 0
                    # log.info(f"  {direction} move to: ({X}, {Y})")
            log.info(f"{direction} to bound: ({X}, {Y})")
        else:
            now = int(X) if direction in "ws" else int(Y)
            while abs((int(X) if direction in "ws" else int(Y)) - now) != aim:
                click, res = send(direction)
                if click:
                    log.info(f"click at    ({X}, {Y})")
                    pygame.display.update()
                    pygame.draw.circle(screen, RED, [20 + Y*10, 20 + X*10], 10, 2)
                    pygame.display.update()
                if "Cannot be moved" not in res:
                    update_value(direction, float(res.split()[2]))
                else:
                    log.info(f"Can't move to {aim} in {direction}")
                    break
            log.info(f"{direction} move to:  ({X}, {Y})")
            return True

    move("w")
    move("d")
    X, Y = 0, 75 # 固定起始位置

    def w(cnt=1): # 便于交互
        for _ in range(cnt):
            move("w", 1)
            pygame.draw.circle(screen, BLUE, [20 + Y*10, 20 + X*10], 5, 5)
            pygame.display.update()
    def a(cnt=1):
        for _ in range(cnt):
            move("a", 1)
            pygame.draw.circle(screen, BLUE, [20 + Y*10, 20 + X*10], 5, 5)
            pygame.display.update()
    def s(cnt=1):
        for _ in range(cnt):
            move("s", 1)
            pygame.draw.circle(screen, BLUE, [20 + Y*10, 20 + X*10], 5, 5)
            pygame.display.update()
    def d(cnt=1):
        for _ in range(cnt):
            move("d", 1)
            pygame.draw.circle(screen, BLUE, [20 + Y*10, 20 + X*10], 5, 5)
            pygame.display.update()

    while True:
        pygame.display.update()
        pygame.draw.circle(screen, BLUE, [20 + Y*10, 20 + X*10], 5, 5)
        pygame.display.update()
        op = input("> ")
        exec(op)
    ```

结果：
![](/assets/images/writeups/tqlctf2022/nanomaze.jpg)

nano 给的标准地图：
![](/assets/images/writeups/tqlctf2022/maze.jpg)
就是 revomaze 的地图，[这个视频](https://www.bilibili.com/video/av720802187)的最后有建模演示