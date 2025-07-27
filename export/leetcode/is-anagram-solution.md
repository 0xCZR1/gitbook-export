---
hidden: true
---

# Is Anagram - Solution

## Understanding the problem:

Given two strings `s` and `t`, return `true` if `t` is an anagram of `s`, and `false` otherwise.

**Example 1:** **Input:** s = "anagram", t = "nagaram" **Output:** true

**Example 2:** **Input:** s = "rat", t = "car" **Output:** false

**Constraints:** `1 <= s.length, t.length <= 5 * 104` `s` and `t` consist of lowercase English letters.

Initial approach (fails due to time complexity being O(n2)):

```python
def isAnagram(self,s: str,t: str) -> bool:  
    s_list = list(s)  
    t_list = list(t)  
    points_needed = len(s_list)  
    points = 0  
    used_positions = []  
    if len(s_list) != len(t_list):  
        return False  
  
    for i in range(len(s_list)):  
        for j in range(len(t_list)):  
            if j not in used_positions and s_list[i] == t_list[j]:  
                points += 1  
                used_positions.append(j)  
                break  
  
    if points == points_needed:  
        return True  
    else:  
        return False  
  
if __name__ == '__main__':  
    test_cases = [  
        ('hello', 'olleh'),  
        ('test', 'sett'),  
        ('cat', 'tac'),  
        ('python', 'typhon'),  
        ('bad', 'dad')  
    ]  
    for s, t in test_cases:  
        print(f"Testing: {s}, {t}:")  
        anagram_finder(s, t)
```

<figure><img src="../.gitbook/assets/image (106).png" alt=""><figcaption></figcaption></figure>

I decided to use a hash map (dictionary), so that I can reduce the time complexity from O(n2) to O(n).

```python
class Solution:
    def isAnagram(self,s: str,t: str) -> bool:
        if len(s) != len(t):
            return False
            
        hash_map = {}
        for char in s:
            hash_map[char] = hash_map.get(char, 0) + 1

        for char in t:
            if char not in hash_map or hash_map[char] == 0:
                return False
            hash_map[char] -= 1

        return True

if __name__ == '__main__':
    s = "anagram"
    t = "nagaram"
    solution = Solution()
    solution.isAnagram(s, t)
```

It's been accepted! Let's gooo!!

<figure><img src="../.gitbook/assets/image (105).png" alt=""><figcaption></figcaption></figure>

## Explanation of hash\_map.get:

```python
# Let's count letters in "cat" using a hash map
hash_map = {}  # Empty hash map to start

# For character 'c':
# hash_map.get('c', 0) -> returns 0 because 'c' isn't in hash map yet
# So: hash_map['c'] = 0 + 1
hash_map = {'c': 1}

# For character 'a':
# hash_map.get('a', 0) -> returns 0 because 'a' isn't in hash map yet
# So: hash_map['a'] = 0 + 1
hash_map = {'c': 1, 'a': 1}

# For character 't':
# hash_map.get('t', 0) -> returns 0 because 't' isn't in hash map yet
# So: hash_map['t'] = 0 + 1
hash_map = {'c': 1, 'a': 1, 't': 1}

# Final hash_map shows each character appears exactly once

```

Here's how it would look when counting "hello":

```python
# Start with empty hash map
hash_map = {}

# Count each character:
# 'h' -> hash_map['h'] = 1
# 'e' -> hash_map['e'] = 1
# 'l' -> hash_map['l'] = 1
# 'l' -> hash_map['l'] = 2  # Notice the count increases for second 'l'
# 'o' -> hash_map['o'] = 1

# Final hash_map = {'h': 1, 'e': 1, 'l': 2, 'o': 1}
```

