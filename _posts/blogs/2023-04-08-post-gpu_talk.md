---
title: "Talk at IIT Bombay: GPU - Security and Reliability"
last_modified_at: 2023-04-08
categories:
  - Blog
tags:
  - Computer Architecture
  - GPU
  - Side Channel Attacks
  - Cybersecurity
  - GPU vs CPU
---

Nowadays, GPUs are used in many applications like AI/ML, Graphics, HPC, cybersecurity etc. GPUs give high speeds for these applications as compared to CPUs. The popularity of GPUs has increased over the last few years and is expected to rise more than CPUs in the coming years. I always used to wonder how these GPUs could speed up tasks. Then I attended a talk on GPUs as part of my computer architecture course. This blog is a summary of the things I learnt in the talk.

But there are various challenges for GPUs. Scalability is one of the biggest challenge faced by GPU industry. The limit on size of GPUs makes it tough to make new GPUs with higher performance. If one needs higher performance, the user has to use multiple independent GPUs and set it up to get higher performance. GPUs specialized for specific tasks are also being manufactured to improve performance in specialized tasks. Approximate computing also gives a possible solution to the problem of scalability. Many applications can go with low-precision calculations.

Moreover, there are various questions on how secure or reliable are these GPUs. There are many known security threats in GPUs. One such timing based side-channel attack to recover AES key is also briefly talked about in this blog.

## CPU v/s GPU
CPUs are optimized for running sequential code whereas GPUs are optimized for parallel code. CPUs have small number of cores and are optimized to reduce latency. On the other hand, GPUs have large number of cores with optimisations to increase throughput.


## GPU — A Closer Look

In an execution model using discrete GPUs, sequential parts of code are run on CPU and parallel code sections are run on GPU. The memory access becomes a major bottleneck. When thousands of cores try to access different memory area, the memory bandwidth limitations limits the speed of GPUs. To increase this throughput, we use Coalescing Unit and MSHRs. Each Streaming Multiprocessor(SM) unit has a Coalescing Unit. This joins byte addresses such that minimum number of words are accessed from memory. Here is an example:

Consider that different threads requested for bytes at 0x00,0x02,0x03 addresses. Without this Coalescing unit, there would be three requests to memory. On the other hand, this coalescing unit only requests a word at address 0x00. This includes bytes at all the required addresses.

Each Streaming Multiprocessor Unit consists of various Processing Elements connected to a load/store unit consisting of Coalescing Unit. Each such SM unit has it’s own L1 cache and it’s MSHR. Various such SM units (+their L1 caches) are connected to L2 cache using an interconnect. To reduce memory bandwidth usage, caches use a Miss Status Handling Registers.

## GPU: Are they Secure?

The various optimizations used in GPUs lead to various security threats. GPUs tend to leak information like encryption keys. Here is a execution-timing based attack model on GPUs.

Consider that a server is running an encryption process on GPU. A client can connect to the server and send plaintext. The server responds with the ciphertext for the plaintext. The attacker can send various plaintexts and get a measure for execution time needed for encrypting the plaintext. This information can be used to reduce the key space. Why does this happen? This is because of the Coalescing Unit. Based on the time of execution, one can guess the amount of coalescing. Using this, the key space is reduced a lot and one can recover the AES key using analysis of correlations.

One of the ways to mitigate this is to turn the coalescing unit off but this leads to 178% performance drop which increases as plaintext size increases. Other better solutions include random coalescing or some software solutions. In random coalescing, the coalescing unit randomly selects some of the addresses to not combine. This has low performance overhead but improves the security. Another software solution may include ensuring that the ciphertext is always produced after a fixed amount of time so that no timing-based side channel attack can be performed.

## GPUs — Reliability
GPUs suffer with low reliability. Errors induce easily in GPU cores. Some errors include soft errors — High energy radioactive particles cause but flips. Other maybe permanent and other faults. This leads to Silent Data Corruption and hence incorrect outputs. If the system hangs or crashes due to these errors, one may need to run the application again. Long-running applications like various large scale models for AI/ML etc. are severely impacted by these kind of errors. Silent Data Corruption in critical applications may cause serious issues.

To make GPUs more reliable, various protection mechanisms are used which include:

- Error Checking and Correction (ECC)
    Single Bit error correction and double bit error detections
- Selective re-computation
- Duplication/Triplication
- Checkpointing

Most of the available ways are costly and not that effective. One of the way is to protect only certain fractions of memory instead of all the memory. Protecting only Hot Memory(i.e. Highly accessed/shared memory fractions) can make GPUs more reliable and help keep the cost of Error Correction or Checking low. Source Code profiling can help to identify these hot memory regions. A simple and easy way to protect the memory is duplication.

## Conclusion

GPUs are good for providing high throughput but at the same time, GPUs still need a lot of work to improve their scalability, reliability and security. Reliability and Security are very important aspects and need to be fixed for better growth of GPU industry. We need solutions which don’t slow the GPUs a lot but keep them reliable and ensure data security.
