for i in {1..1000}; do ltrace ./chall4 $(python3 exploit_buffer_overflow.py) 2>&1 | grep -E "^strcpy" | sed s/'strcpy('// | cut -d "," -f 1 >> aslr-analyse.txt; done

