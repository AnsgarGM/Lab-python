#!/bin/bash

/home/zoilom/Documentos/AnalisisyDetecciondeMalware/Lab-python/goodware/crud &

pid=$!

gcore -o crud_gcore.log $pid
