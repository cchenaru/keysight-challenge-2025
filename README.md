# Keysight Challenge 2025

## Intro
Welcome to the Keysgiht Challenge 2025. In this challenge you will have to run code on the GPU and demonstrate your skills in parallelizing the code for better performance.

The main description of the task is in this [document](https://docs.google.com/document/d/1-A59iiqdzbKEcdTZGfll-y3Vl6Kw7nMEBiraD2W86pU/edit?usp=sharing).

### On a Linux System
    * Build the gpu-router application
      git clone $YOUR_GITHUB_FORK
      cd keysight-challenge-2025
      mkdir build
      cd build
      cmake ..
      make VERBOSE=1

    * Run the program
      make run

    * Clean the program
      make clean
