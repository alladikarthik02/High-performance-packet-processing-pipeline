# Challenge Log — pktpipe

These are the **real** engineering problems we hit while building `pktpipe` in this session —
nothing invented, nothing "typical." Each one is something that actually broke, actually failed
to compile, or actually turned out to be wrong when measured. They're written in plain English
for someone who is learning, so every piece of jargon is defined the first time it shows up.

The project itself: a program that reads network **packets** (small chunks of data sent over a
network), works out what protocols they use, and checks them against a list of rules — like a
firewall. It's written in C and C++ and captures live traffic on Linux. Most of these
challenges are about the gap between "the code looks right" and "the code is right."

---

## CHAL-001 — The PDF résumé wouldn't open the normal way

- **Date/phase:** Session start / reading the project spec
- **Status:** Resolved

### What we were doing
The whole project is built to back up a résumé bullet point. So the first step was reading the
résumé PDF to see exactly what it claimed. I tried to open it with the built-in file reader.

### Background
A **PDF** stores text in a way that isn't plain text — you need a tool to pull the words out.
One common tool renders each page into an image first; another reads the text directly.

### What went wrong
```
pdftoppm is not installed. Install poppler-utils ...
```
The image-rendering path needed a tool called `poppler` that wasn't on the machine.

### Why
The default way of reading a PDF here tries to turn pages into pictures, and that needs an extra
program that simply wasn't installed.

### Fix
Instead of installing anything, I used a Python library called `pypdf` that was **already
present** to pull the text straight out. No install, same result.

### Takeaway
Before installing new tools, check what's already on the machine — the cheaper path is often
already there.

---

## CHAL-002 — The résumé says "Linux," but the computer is a Mac

- **Date/phase:** Planning / choosing where to build
- **Status:** Resolved (by deciding to build inside Linux via Docker)

### What we were doing
The résumé bullet says the project "worked against the **Linux networking stack**." The stack is
just the part of the operating system that handles network traffic. But the machine we're
building on is a Mac (Apple silicon), not Linux.

### Background
- **Capturing packets** means asking the operating system for copies of network traffic.
- Linux offers a specific door for this called **`AF_PACKET`** — a special kind of network
  connection that hands you raw traffic.
- macOS does **not** have `AF_PACKET` at all. It uses a completely different door called
  `/dev/bpf`.
- **Docker** is a tool that runs a real, tiny Linux system inside a lightweight box on your Mac.

### What went wrong
Not a crash — a truth problem. If we built the whole thing on macOS, the résumé's "Linux
networking stack" claim would be false, and the first interview question ("did you use
`AF_PACKET`?") would expose it. Writing Linux-only code but never running it would be a bluff.

### Why
`AF_PACKET` is Linux-only. There is no way to make that specific claim true on a Mac.

### Fix
Build and run the whole project **inside a real Linux system** using Docker. Then the socket,
the shared buffer, the virtual network cards — all of it is genuine Linux, not a simulation.

### Takeaway
When a claim names a specific technology, build on the platform where that technology is real —
don't fake the environment and hope the difference never comes up.

---

## CHAL-003 — Docker Desktop wouldn't accept connections

- **Date/phase:** Setting up the Linux environment
- **Status:** Resolved (user restarted it)

### What we were doing
Trying to start Docker so we could build inside Linux.

### Background
Docker has two parts: an **app** you can see, and a background **daemon** (a program that runs
silently and does the actual work). Commands talk to the daemon.

### What went wrong
```
request returned 500 Internal Server Error ... check if the server supports the requested API version
```
The Docker app was running, and its connection file existed, but the daemon behind it refused
every command.

### Why
The daemon had gotten into a bad state — the visible app was up but the engine behind it wasn't
answering. This is a known first-launch quirk.

### Fix
The user restarted Docker. After the restart it came up in about 10 seconds and reported a real
Linux kernel (version 6.12). We didn't fully diagnose the original bad state — restarting
cleared it.

### Takeaway
When a service's front-end is up but its back-end refuses everything, a clean restart is worth
trying before deep debugging.

---

## CHAL-004 — Docker couldn't download its base image ("credential helper not found")

- **Date/phase:** Building the Linux environment image
- **Status:** Resolved

### What we were doing
Building the Linux "image" — a recipe file (the `Dockerfile`) that lists everything to install.
The first line downloads a base Linux system to build on.

### Background
- A **credential helper** is a little program Docker uses to look up saved logins so it can
  download images.
- **`PATH`** is the list of folders your shell searches when you type a command. If a program
  isn't in one of those folders, the shell says "not found" even if it exists elsewhere.

### What went wrong
```
error getting credentials - err: exec: "docker-credential-desktop": executable file not found in $PATH
```
The download failed because Docker couldn't find its own credential helper.

### Why
Docker's config said "use the helper named `docker-credential-desktop`," but that helper lived
inside the Docker app folder, which wasn't on the shell's `PATH`. So the shell couldn't find a
program that was actually right there on the disk — like a book that's in the library but not on
the shelf the librarian checks.

### Fix
Added the Docker app's internal folder to `PATH` **for that one command only**, so we didn't
have to permanently change the user's Docker settings. The download then worked.

### Takeaway
"Not found" usually means "not found *on the search path*," not "not on the computer" — point
the tool at the right folder rather than reinstalling.

---

## CHAL-005 — A subtle C bug in the very first file (undefined behavior inside a macro)

- **Date/phase:** T0 — first file compiled
- **Status:** Resolved

### What we were doing
Writing the first small C file, which builds a text string describing the build (OS name, CPU
type, etc.).

### Background
- The **preprocessor** is a step that runs before real compilation. Lines starting with `#`
  (like `#if defined(__APPLE__)`) are its instructions — it uses them to include or exclude
  chunks of code depending on the platform.
- A **macro** is a name that the preprocessor expands into something else before compiling.
- `snprintf` is a standard function for building strings — but it's *allowed* to secretly be a
  macro instead of a real function, and on some systems it is.

### What went wrong
The compiler printed six warnings:
```
warning: embedding a directive within macro arguments has undefined behavior
```

### Why
I had put `#if defined(__APPLE__)` lines **inside** the parentheses of a `snprintf(...)` call,
to pick "macOS" vs "Linux" right there. That's fine if `snprintf` is a real function — but if
it's secretly a macro, the C standard says putting a `#` directive inside its arguments is
**undefined behavior** (meaning: the compiler is allowed to do literally anything, and different
compilers do different things). "It worked today" is exactly the trap — undefined behavior often
works until you change compiler or platform, then silently breaks.

### Fix
Moved the platform choices out to the top of the file as named constants (`PP_OS_NAME`, etc.),
then passed those clean names into `snprintf`. Now no `#` directive is ever inside a function
call.

### Takeaway
Code that compiles and gives the right answer can still be broken — "undefined behavior" is a
bug that's just waiting for the day the environment changes.

---

## CHAL-006 — A shell trick made a test result look wrong (`exit code: 0`)

- **Date/phase:** T1 — proving a safety check works
- **Status:** Resolved (it was a reporting mistake, not a real problem)

### What we were doing
Demonstrating that a compile-time safety check would correctly **reject** a bad change by
failing the build.

### Background
In a shell, when you pipe commands together (`command | head`), the special variable `$?` that
reports "did it succeed?" reports the result of the **last** command in the pipe, not the first.

### What went wrong
The compiler correctly failed (which was the goal), but my summary line printed
`compiler exit code: 0` — which reads as "it succeeded," the opposite of what happened.

### Why
`$?` captured the exit code of the `head` command at the end of the pipe, not the compiler at
the start. The compiler really did fail; my measurement of that fact was wrong.

### Fix
I flagged the mistake honestly in the moment. The compiler's error message itself was the real
proof, so nothing needed re-running.

### Takeaway
When measuring whether something failed, make sure you're reading the result of the *thing you
care about*, not the last thing in the pipe.

---

## CHAL-007 — A C++-only trick didn't compile in C (alignment on a struct)

- **Date/phase:** T1 — the packet metadata layout
- **Status:** Resolved

### What we were doing
Defining the core data structure (`pp_meta`) that describes each packet, and asking the compiler
to align it to a **cache line** (the fixed-size chunk — 64 bytes — that a CPU always moves
between memory and its fast cache; keeping the struct to one line means one memory fetch, not
two).

### Background
- **Alignment** means forcing a piece of data to start at a memory address that's a multiple of
  some number.
- C and C++ are different languages with slightly different grammar. This project's header files
  are read by **both** a C compiler and a C++ compiler, so they must be valid in both.

### What went wrong
```
error: use of undeclared identifier 'pp_meta'
```
...repeated for every place the type was used. Confusing, because the real problem was somewhere
else entirely.

### Why
I wrote the alignment keyword *between* the words `struct` and the type's name. That's legal in
C++ but **illegal in C** — C's grammar has no slot for it there. So in C, the whole type
definition failed to parse, the type `pp_meta` was never created, and every later mention of it
cascaded into "undeclared identifier." The error pointed at the symptoms, not the cause.

### Fix
Moved the alignment keyword onto the struct's **first field** instead. That spelling is legal in
both C and C++, and it still forces the whole struct to be aligned.

### Takeaway
When a header is shared between two languages, it must obey the stricter grammar of both — and a
pile of "undeclared" errors often means one real parse failure higher up.

---

## CHAL-008 — Code that compiled on Mac broke instantly on Linux (`MAP_ANONYMOUS`)

- **Date/phase:** First build inside the Linux container
- **Status:** Resolved

### What we were doing
Moving the project into Linux (per CHAL-002) and compiling it there for the first time. The
memory allocator uses `mmap`, a system call that asks the OS for a big block of memory.

### Background
- **POSIX** is the shared standard that Unix-like systems (Linux, macOS) mostly agree on.
- Some features are **extensions** — extra things a particular system adds beyond the standard.
- **`MAP_ANONYMOUS`** is a flag for `mmap` meaning "give me blank memory, not a file." It is one
  of those non-standard extensions.
- A **feature-test macro** is a line like `#define _DEFAULT_SOURCE` that tells the C library
  "please also expose the non-standard extras."

### What went wrong
```
error: 'MAP_ANONYMOUS' undeclared (first use in this function)
```
The exact same file that compiled cleanly on the Mac failed to compile on Linux.

### Why
We compile in **strict standard mode** (only guaranteed-standard features). In that mode, the
Linux C library *hides* non-standard extras like `MAP_ANONYMOUS` unless you explicitly ask for
them. Apple's headers hand it to you no matter what. So the code looked portable but secretly
relied on Apple being lenient.

### Fix
Added `#define _DEFAULT_SOURCE` at the very top of the file (it has to come *before* any system
header, because the headers decide what to expose the moment they're read). Kept strict mode on
purpose, because strict mode is what *caught* the hidden dependency in the first place.

### Takeaway
"It compiles on my machine" can hide a non-portable dependency — building on the real target
platform is what surfaces it, and strict mode is a feature, not an annoyance.

---

## CHAL-009 — The same CPU reported two different cache-line sizes

- **Date/phase:** T1 — verifying the cache-line assumption
- **Status:** Resolved (turned out to *confirm* the design)

### What we were doing
The whole layout design rests on the cache line being 64 bytes. Before trusting that, I asked
the machine what its cache line size actually was.

### Background
A **cache line** is the fixed chunk size the CPU moves between memory and cache. Different chips
use different sizes. You can ask the OS what it is.

### What went wrong
Not an error — a contradiction. The **same physical chip** gave two different answers depending
on who asked:
- macOS said **128 bytes**
- The Linux system (running on that same chip, inside Docker) said **64 bytes**

### Why
Docker runs Linux inside a virtual machine, and the virtualization layer doesn't pass the chip's
true cache details through to the guest. Neither number is a lie — they're answering slightly
different questions. But it means "the cache line size" isn't a single fixed fact you can look
up; it depends on who's reporting it.

### Fix
No code change needed — this *validated* the existing choice. The design targets **64 bytes**,
the smaller of the two. A structure that fits in 64 also fits in 128, so designing for the
smaller number is safe everywhere. If we'd trusted the Mac's 128, the structure would have been
too big and would have spilled across two cache lines on the very machine we test on.

### Takeaway
Hardware facts reported by software can depend on the layer reporting them — design for the
strictest number, and always say which machine and which tool a performance number came from.

---

## CHAL-010 — A test bug: using 0 to mean "not set," when 0 is a real value

- **Date/phase:** T2 — the Ethernet/VLAN parser tests
- **Status:** Resolved

### What we were doing
Writing tests for the packet parser. A test helper let you say "pretend we only captured N bytes
of this packet" to test truncated input. If you didn't specify N, it should default to the full
packet.

### Background
- **caplen** = how many bytes we actually captured (could be less than the full packet).
- A **sentinel** is a special value that means "nothing here / not provided" — like leaving a
  form field blank.

### What went wrong
```
FAIL test_l2.cpp:265: CHECK(m.caplen <= n)
```
One test out of 327 failed — specifically the case where the captured length was **0**.

### Why
My helper used `0` to mean "caller didn't specify a length, so use the whole packet." But `0` is
also a **completely valid capture length** — it means "we captured nothing." So when a test
genuinely asked for "0 bytes captured," the helper misread it as "not specified" and quietly
substituted the full packet. The test then saw a bigger length than it asked for.

The irony: this is the **exact same mistake** the parser is designed to avoid elsewhere (using 0
as "no VLAN" when VLAN 0 is real). I wrote a warning about it in the code, then made it myself
~200 lines later.

### Fix
Changed the "not set" sentinel to a value that can never be a real capture length (the maximum
possible 32-bit number), so 0 is free to mean genuinely-zero.

### Takeaway
Never use a valid value as your "empty" marker — pick something the real data can never be. And
knowing about a bug class doesn't make you immune to it.

---

## CHAL-011 — tests passed on a broken test corpus; tcpdump caught it

- **Date/phase:** T5 — generating test packet files
- **Status:** Resolved

### What we were doing
Generating `.pcap` files (standard packet-capture files) full of synthetic packets, to feed the
pipeline for testing and benchmarking. Then I opened one with `tcpdump` (the standard
packet-inspection tool) as a sanity check.

### Background
- Every IP packet has a **Total Length** field: the sender declaring how long it is.
- A packet's header is written *before* its payload exists, so length fields normally get filled
  in afterward.

### What went wrong
tcpdump showed:
```
22:13:20.000000 IP 192.168.1.68 > 10.0.92.137: [|tcp]
```
The `[|tcp]` means tcpdump thought every packet was **truncated** — cut off before the TCP part.
But the packets were complete.

### Why
My generator set each packet's Total Length field to just the *header* length, never updating it
to cover the payload. My own parser **deliberately ignores** that field (for good security
reasons — see CHAL-016), so my tests were perfectly happy. But tcpdump *trusts* the field, saw
"length = 20," and concluded there was no room for the TCP data.

The deeper point: **my tests couldn't catch this because they checked my code against my code.**
Both my generator and my parser shared the same blind spot. An outside tool with different
assumptions found it in one command.

### Fix
Added "back-patch" helpers that fill in each length field correctly once the whole packet is
built. After that, tcpdump decoded every packet perfectly, including the tunneled ones.

### Takeaway
A test suite that only checks your code against your own code agrees with itself by construction
— cross-check against an independent tool that made different assumptions.

---

## CHAL-012 — I mis-sized a struct because I didn't add up the bytes

- **Date/phase:** T6 — the compiled rule structure
- **Status:** Resolved

### What we were doing
Defining `pp_rule`, the compact structure that holds one firewall rule. The design requires it
to be exactly 32 bytes so two rules fit neatly in one cache line.

### Background
- **Padding**: compilers insert invisible gaps between fields so each field lands on a
  convenient address. A 2-byte field followed by a 4-byte field usually gets 2 bytes of hidden
  padding so the 4-byte field is aligned.
- A **compile-time assertion** (`static_assert`) is a check the compiler runs; if it's false,
  the build fails.

### What went wrong
```
error: static assertion failed: pp_rule must be 32 bytes: two per cache line
```
The struct came out as **40 bytes**, not 32.

### Why
I declared the fields in a careless order — a 2-byte field right before a 4-byte field — which
forced the compiler to insert hidden padding, and the total ballooned. I'd written the field
list from memory without actually adding up the sizes.

### Fix
Two real improvements, not just a workaround:
1. Reordered the fields widest-first so no hidden padding is needed.
2. Deleted a redundant field (a rule ID that was always just "position + 1," so it can be
   computed instead of stored) and packed two tiny fields into one byte.
The struct landed at exactly 32 bytes.

### Takeaway
Field *order* changes struct size because of padding — put the widest fields first, and let a
compile-time size check guard the number so it can't silently drift.

---

## CHAL-013 — A missing `#include` after refactoring

- **Date/phase:** T6 — rule language tests
- **Status:** Resolved

### What we were doing
Compiling the tests for the rule language.

### Background
An **`#include`** line pulls in definitions from another file. If you use a name (like a
constant) that's defined elsewhere, you must include the file that defines it.

### What went wrong
```
error: 'PP_IPPROTO_TCP' was not declared in this scope
```
The test used protocol constants like `PP_IPPROTO_TCP` but couldn't find them.

### Why
I had deliberately kept the rules header lightweight — it does *not* pull in the protocol
definitions, on purpose. The test needed those constants but never included the file that
defines them.

### Fix
Added the missing `#include "pp/proto.h"` to the test file.

### Takeaway
Deliberately minimal headers are good design, but they push the responsibility onto callers to
include what they actually use.

---

## CHAL-014 — The fuzzer wouldn't link ("cannot find libclang_rt")

- **Date/phase:** T14 — building the fuzz tester
- **Status:** Resolved

### What we were doing
Building a **fuzzer**: a tool that throws millions of random inputs at the parser to find
crashes nobody thought to test for. It's built with special compiler options that add safety
instrumentation.

### Background
- **Linking** is the final build step that stitches compiled pieces together into a runnable
  program.
- **Sanitizers** (ASan, UBSan) and **libFuzzer** are helper libraries the compiler adds. Their
  code lives in special runtime library files.
- On Debian Linux, the compiler and those runtime libraries are shipped as **separate packages**
  — installing the compiler does not install them.

### What went wrong
```
/usr/bin/ld: cannot find .../libclang_rt.fuzzer-aarch64.a: No such file or directory
```
The code compiled fine, then failed at the final linking step — it couldn't find the fuzzer and
sanitizer runtime files.

### Why
Our Linux image installed the Clang compiler but not its separately-packaged runtime libraries.
So the compiler happily accepted `-fsanitize=fuzzer` and then, at link time, went looking for
support files that were never installed. The error looks like a code problem but is really a
missing-package problem.

### Fix
Added the runtime package (`libclang-rt-14-dev`) to the Dockerfile — fixing it at the source, so
the environment rebuilds correctly for anyone, rather than hand-patching one container.

### Takeaway
"Compiles but won't link" often means a missing *library*, not a code bug — and on some Linux
distributions the compiler's own runtime is a separate package you have to ask for.

---

## CHAL-015 — A benchmark that hung forever (and left a container running)

- **Date/phase:** T12 — comparing the two capture methods
- **Status:** Resolved

### What we were doing
Comparing two ways of capturing live packets: the simple "ask the kernel one packet at a time"
method, and the fast "shared buffer" method. The test sends traffic on one virtual network card
and captures it on another.

### Background
- A **system call** (syscall) is a request to the operating system. Each one is relatively slow.
- `MSG_DONTWAIT` means "if there's no packet right now, return immediately instead of waiting."
- `poll()` is a call that says "sleep until there's actually something to do" — the polite way
  to wait.
- A **busy-spin** is a loop that keeps asking "anything yet? anything yet?" as fast as possible,
  pinning a CPU core at 100% for no benefit.

### What went wrong
The benchmark **timed out after 7 minutes** instead of finishing, and left a Docker container
running in the background for 23 minutes.

### Why
In the simple capture method, when no packet was ready, the code returned "0 packets" and the
caller immediately asked again — forever, as fast as possible, on an idle link. It never slept
and never checked the stop condition (which was only checked after receiving packets). So on a
quiet moment it spun a core at 100% and never made progress.

### Fix
When there's nothing to receive, call `poll()` to actually sleep until traffic arrives —
mirroring what the fast method already did correctly. The two methods should differ in *how they
get packets*, not in whether they melt a CPU when there are none.

### Takeaway
"Returns the correct value" and "behaves correctly" are different — a function can return a
perfectly correct "nothing yet" while burning a whole CPU core doing it.

---

## CHAL-016 — Two "optimizations" that measurement proved made things worse

- **Date/phase:** T12 — benchmarking
- **Status:** Resolved (both turned off, based on data)

### What we were doing
Benchmarking two textbook speed tricks: **batching** (process 32 packets at a time instead of
one) and **software prefetch** (tell the CPU "you'll need this memory soon, start fetching it").
I had confidently written in the spec that both would help.

### Background
- **Prefetch**: a hint to the CPU to start loading data before you use it, to hide the delay of
  fetching from slow memory.
- The **hardware prefetcher** is a feature already built into the CPU that automatically detects
  simple patterns (like reading memory straight through) and fetches ahead on its own.

### What went wrong
The measurements contradicted my own spec:
- **Batching:** a batch of 2–4 was fastest; my chosen default of 32 was **4–9% slower**, and 256
  was up to **16% slower**.
- **Software prefetch:** at best it did nothing; at a distance of 32 it was **45% slower** on the
  varied-traffic test.

### Why
Both tricks assumed conditions that weren't true here:
- Batching pays off by saving *system calls* — but replaying from a file has no per-packet system
  calls to save.
- Software prefetch pays off when memory reads are *unpredictable* — but we read the packet file
  straight through, which the CPU's **hardware** prefetcher already handles perfectly. My extra
  software prefetch just wasted memory bandwidth and, at long distances, kicked out data we were
  about to use.

Importantly, batching *does* help enormously in the real live-capture case (see CHAL-017), where
system calls are the bottleneck. It just doesn't help file replay.

### Fix
Turned software prefetch **off** by default (changed the default distance to 0). Kept batching at
32 because it's essential for live capture, and documented that its value is about system calls,
not memory layout.

### Takeaway
An optimization you haven't measured is a guess — and guesses are wrong in both directions. I
implemented prefetch because the textbook says to, and it made things up to 45% *worse*.

---

## CHAL-017 — The live-capture measurement was blaming idle time on the code

- **Date/phase:** T13 revisit — after resuming the project
- **Status:** Resolved

### What we were doing
Reporting how fast the pipeline processes packets during **live** capture (real traffic on a
virtual network card).

### Background
- **Wall-clock time** is just "how much time passed on a clock," including any time spent
  waiting.
- Live capture spends most of its time *asleep*, waiting for the next packet to arrive.

### What went wrong
Live capture reported a nonsensical **0.021 million packets/second** and **48,720 nanoseconds per
packet** — numbers that suggested the code was catastrophically slow, when it isn't.

### Why
I measured "total time from start to finish" and divided by packet count. But on a quiet link,
almost all of that time was spent *waiting for the sender to send*, not processing. So I was
dividing ~1 second of mostly-sleeping by the packet count and calling the result "processing
speed." It measured how long the program ran, not how fast it works. This is the worst kind of
bug: a wrong number that looks like a real result and might get quoted.

### Fix
Added a **second clock** that only counts time spent actually parsing and classifying, excluding
the waiting. The report now separates "how fast traffic arrived" (the sender's pace) from "how
fast we process" (our real speed). This second clock is opt-in, because reading the clock costs a
little time — fine during live capture (which is mostly idle anyway) but skipped during
benchmarks where it would distort the very number being measured.

After the fix, live capture reported **~29 ns/packet** — which independently matched the
**~23 ns/packet** from the file-replay benchmark. Two separate measurement paths agreeing is
strong evidence both are right.

### Takeaway
When you measure "per-packet cost," make sure you're not dividing by time the program spent
asleep — separate "how fast work arrived" from "how fast we did the work."

---

## CHAL-018 — A mysterious 5.8× speed difference, and a wrong first guess

- **Date/phase:** T13 revisit — chasing an unexplained number
- **Status:** Resolved (understood and documented)

### What we were doing
Trying to explain why the same code, on the same packet file, ran at very different speeds: about
**68 nanoseconds per packet** on a single pass, but about **19 ns/packet** when we replayed the
file 20 times.

### Background
- **CPU cache**: a small pool of very fast memory. Data you've used recently is "warm" (in cache,
  fast); data you haven't touched is "cold" (in slow main memory).
- A **page fault** is what happens the first time your program touches a chunk of memory the OS
  hasn't set up yet — the OS pauses you to wire it up.
- **L2 cache** on this machine is 4 megabytes.

### What went wrong
The 5.8× gap was unexplained, and my first guess turned out to be wrong.

### Why (first guess — WRONG)
I assumed the slow first pass was **page faults**: the file is 3.8 MB ≈ 927 memory pages, so
surely 927 faults. I measured it (page faults can be counted even without special hardware
support) and found only **172 faults — and the same number whether cold or warm.** So page
faults were *not* the explanation. It turns out Linux "faults-around" — one fault sets up ~16
pages at once — so a 3.8 MB file costs far fewer faults than pages.

### Why (real cause)
The slow first pass is the **memory system warming up**: the first time through, all 3.8 MB of
packet data has to be dragged from slow main memory into cache, the address-translation cache is
cold, and the CPU's branch predictors are untrained. Every later pass finds the data already warm
in cache.

**And this exposed a flaw in my own benchmark:** the packet file is 3.8 MB, and the L2 cache is
4 MB. So replaying the file 20 times means 19 of those passes read data that's **already sitting
in cache** — which flatters the result. A real network card hands you packets that were *just*
placed in memory and are never pre-cached. So the ~19 ns "warm" number is optimistic, and the
~68 ns "cold" number is closer to real-world behavior.

### Fix
No code change — this is a measurement-honesty issue. Documented both numbers, explained that the
warm one benefits from the file fitting in cache, and noted that a better benchmark would use a
file several times larger than the cache. That improvement is identified but **not yet done**.

### Takeaway
When a benchmark's data fits in cache, it measures a warm memory system, not real-world speed —
and always verify *why* something is slow before believing your first explanation.

---

## CHAL-019 — The parser trusts the memory limit but ignores the protocol's own length

- **Date/phase:** Post-build review (raised by the user)
- **Status:** **Open** — understood and explained, fix not yet applied

### What we were doing
Reviewing the parser after the main build was done. The user pointed out a real flaw in how the
parser decides where a packet's payload ends.

### Background
- **Ethernet minimum frame size:** every Ethernet frame must be at least 60 bytes. If your real
  data is smaller, the network card appends meaningless filler called **padding** to reach 60.
- **caplen:** how many bytes we actually captured — the hard memory-safety limit (read past it
  and you crash).
- **IP Total Length:** a field where IP declares its own real length — the only thing on the
  wire that says where the real data ends and padding begins.

### What went wrong
For a small packet that got padded, the parser reports the **padding** as if it were real
payload. Example: a 42-byte packet padded to 60. The parser says "payload = 18 bytes" (the
leftover), when the IP Total Length field says the real payload is 0 bytes.

### Why
There are really **two different boundaries**, and the code only implements one:
- The **memory-safety** boundary = `caplen` (never read past this, or you crash). ✅ Implemented.
- The **semantic** boundary = where the protocol says its data ends. ❌ Not implemented.

The correct rule is: *the payload ends at whichever comes first — the captured bytes, or where IP
says it ends.* The code only uses "leftover captured bytes," so trailing padding leaks in as
payload. The IPv6 version of this field isn't read at all — the constant for it exists in the
code but is never used.

The root cause is that I over-applied a good rule. The rule "don't trust length fields" is
correct against attackers who claim to be *bigger* than they are (which would cause a crash). But
I turned it into "ignore length fields entirely," which also throws away the safe, useful case: a
length field claiming to be *smaller* can only ever make us read less, which is always safe.
Untrusted doesn't mean unusable — it means *clamp it, don't obey it blindly*.

### Why no test caught it
Every test packet was built with its length field set to *exactly* match its real content (see
CHAL-011's fix), so no test ever had padding. The one situation that exposes the bug is the one
the test builder can't produce. The fuzzer didn't catch it either, because it only checks for
*memory* violations (reading past the end) — and this bug is memory-safe. It's a "we counted the
wrong thing" bug, not a "we crashed" bug.

### Impact (honest scoping)
Today this is a correctness bug in the reported payload length, not a live security hole, because
no rule currently inspects payload *content*. It would become a real problem the moment we added
payload matching, checksum validation, or fragment reassembly. There's a real historical example
(**Etherleak, CVE-2003-0001**) where padding contained leftover kernel memory — if you treat
padding as payload, you'd feed leaked memory into your logic.

### Fix
**Not yet applied.** The remaining design question is *where* the second boundary should live —
computed per protocol layer, or tracked in the shared cursor that walks the packet. Discussed but
deliberately left for a follow-up so the design decision can be made carefully.

### Takeaway
A safety limit and a meaning limit are two different things: `caplen` says "how far is it safe to
read," the protocol's length says "how far is it *meaningful* to read" — you need both, and a
test can't find a bug your mental model doesn't admit exists.

---

## Recurring themes

A few lessons showed up more than once across this build — these are the ones worth internalizing:

1. **A sentinel must be a value the real data can never take.** Using `0` for "none" broke twice
   (CHAL-010) because `0` is a legal value for VLANs, capture lengths, and more.
2. **Your own tests share your own blind spots.** CHAL-011 and CHAL-019 are the same shape: the
   tests agreed with the code because both were built from the same wrong assumption. Outside
   tools (tcpdump) and outside reviewers found what self-testing couldn't.
3. **Measure before believing — including your own optimizations.** CHAL-016 (prefetch made it
   45% worse) and CHAL-018 (wrong guess about page faults) both came from assuming instead of
   measuring.
4. **"Compiles and gives the right answer" is not "correct."** CHAL-005 (undefined behavior),
   CHAL-008 (hidden non-portable dependency), and CHAL-015 (correct return value, melted a CPU)
   all looked fine and weren't.
