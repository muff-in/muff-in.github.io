---
title: "How to get started in CTF?"
date: "2019-03-30"
layout: single
tags:
- ctf, guide
categories:
- ctf
---




##### First, What are CTF Competitions?

Capture the Flag (CTF) is a special kind of information security competition There are three common types of CTFs: Jeopardy, Attack-Defence and mixed.

Jeopardy-style CTFs have a couple of questions (tasks) in a range of categories. For example, Web, Forensic, Crypto, Binary or something else. A team can gain some points for every solved task. More points for more complicated tasks usually. The next task in a chain can be opened only after some team solves the previous task. Then the game time is over the sum of points shows you a CTF winner.

Attack Defence is another interesting kind of competition. Here every team has own network(or only one host) with vulnerable services. Your team has time for patching your services and developing exploits usually. So, then organizers connect participants of the competition and the wargame starts! You should protect own services for defense points and hack opponents for attack points. Historically this is the first type of CTFs, everybody knows about DEF CON CTF — something like a World Cup of all other competitions.

Mixed competitions may vary possible formats. It may be something like wargame with special time for task-based elements


CTF competitions generally focus on the following skills: reverse engineering, cryptography, ACM style programming, web vulnerabilities, binary exercises, networking, and forensics. Pick one and focus on a single topic as you get started.


## Reverse Engineering
I highly suggest that you get a copy of IDA Pro. There is a free version available as well as a discounted student license. Try some crackme exercises. Write your own C code and then reverse the compiled versions. Repeat this process while changing compiler options and program logic. How does an “if” statement differs from a “select” in your compiled binary? I suggest you focus on a single architecture initially: x86, x86_64, or ARM. Read the processor manual for whichever one you choose. Book recommendations include:
{% highlight C %}
>Practical Reverse Engineering

>Reversing: Secrets of Reverse Engineering

>The IDA Pro Book
{% endhighlight C %}
## ACM style programming

Pick a high-level language. I recommend Python or Ruby. For Python, read Dive into Python (free) and find a pet project you want to participate in. It is worth noting that Metasploit is written in Ruby. Computer science classes dealing with algorithms and data structures will go a long way in this category as well. Look at past programming challenges from CTF and other competitions — do them! Focus on creating a working solution rather than the fastest or most elegant solution, especially if you are just getting started.

## Web vulnerabilities

There are many web programming technologies out there. The most popular in CTF tend to be PHP and SQL. The php.net site is a fantastic language reference. Just search for any function you are curious about. After PHP, the next most common way to see web challenges presented is with Python or Ruby scripts. Notice the overlap of skills? There is a good book on web vulnerabilities, The Web Application Hacker’s Handbook. Other than that, after learning some of the basic techniques, you might also think about gaining expertise in a few of the more popular free tools available. These are occasionally useful in CTF competitions too. This category also frequently overlaps with cryptography in my experience.

## Binary exercises 

This is my personal favorite. I recommend you go through reverse engineering before jumping into the binary exercises. There are a few common vulnerability types you can learn in isolation: stack overflows, heap overflows, and format string bugs for starters. A lot of this is training your mind to recognize vulnerable patterns. Looking at past vulnerabilities is a great way to pick up these patterns. You should also read through:
{% highlight C %}
>Hacking: The Art of Exploitation

>The Shellcoders Handbook

> The Art of Software Security Assessment
{% endhighlight C %}

## Forensics

I suggest you learn how to use the 010 hex editor and don’t be afraid to make absurd, wild, random guesses as to what could be going on in some of these problems.
{% highlight C %}
Digital Evidence and Forensics

Computer Forensics (PDF)

Computer Forensics in a LAN Environment (PDF)

Digital Forensics

Forensic Examination of Digital Evidence: A Guide for Law Enforcement (PDF)
{% endhighlight C %}

## Cryptography 

Try with the basic terminology and concepts so that when you read about hashing, Wireless cracking or Password Cracking and encryption technologies. There is a very specialized language for cryptography and encryption. Terms like cipher, plaintext, ciphertext, keyspace, block size, and collisions can make studying cryptography a bit confusing and overwhelming to the beginner. I will use the term “collision,” as there is no other word in plain English that can replace it.

https://null-byte.wonderhowto.com/how-to/hack-like-pro-cryptography-basics-for-aspiring-hacker-0161246/

Books:
{% highlight C %}
>Applied Cryptography

>Practical Cryptography

>Cryptography 
{% endhighlight C %}
source- Google



