#!/bin/bash

interface=$1

ifconfig $interface  | awk '/inet addr/ {split ($2,A,":"); print A[2]}'
