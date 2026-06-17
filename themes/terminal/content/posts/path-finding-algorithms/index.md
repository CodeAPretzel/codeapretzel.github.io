+++
author = "CodeAPretzel"
title = "Path Finding Algorithms"
date = "2024-11-17"
description = "Python script to visualize the A* Algorithm and Manhattan Distance via the terminal."
tags = [
    "python",
    "algorithm",
]
cover = "cover.png"
+++


## INFO -

Originally designed for the 2024 Missouri Hacks Hackathon, at [Py Script](#py-script--), you will see the script used to take an input map and have an object, denoted as a `@` symbol, that navigates the map in the most mathematically efficient possible route to reach its end objective, denoted as a `*` symbol.

---

### Py Script -

{{< code language="py" title="path-finding.py" id="1" expand="Show" collapse="Hide" isCollapsed="false" >}}

"""
Code created by CodeAPretzel,
Pretson G.,
and ChatGPT (for A* algorithm and Manhattan distance in python).

---

Note on "map-data" file:

> = starting point
. = free spaces
@ = object/robot navigating the system
# = obstacles
* = end goal

"""

import math
import time
import sys
import os

def ReadGridFromFile(filePath):
    with open(filePath, 'r') as file:
        return [list(line.strip()) for line in file]

def FindPos(grid, symbol):
    for y, row in enumerate(grid):
        for x, cell in enumerate(row):
            if cell == symbol:
                return (x, y)
    return None

def Heuristic(a, b):
    # Using Euclidean distance for diagonal movement
    return math.sqrt((a[0] - b[0])**2 + (a[1] - b[1])**2)

def GetNeighbors(position, grid):
    x, y = position
    neighbors = []
    directions = [
        (0, -1), (0, 1), (-1, 0), (1, 0),  # Vertical and horizontal directions
        (-1, -1), (1, -1), (-1, 1), (1, 1)  # Diagonal directions
    ]
    
    for dx, dy in directions:
        nx, ny = x + dx, y + dy
        if 0 <= ny < len(grid) and 0 <= nx < len(grid[0]) and grid[ny][nx] != '#':
            neighbors.append((nx, ny))
    return neighbors

def DestinationSearch(grid, start, goal):
    open_set = [start]
    came_from = {}
    g_score = {start: 0}
    f_score = {start: Heuristic(start, goal)}

    while open_set:
        current = min(open_set, key=lambda x: f_score.get(x, float('inf')))
        if current == goal:
            path = []
            while current in came_from:
                path.append(current)
                current = came_from[current]
            path.reverse()
            return path

        open_set.remove(current)
        for neighbor in GetNeighbors(current, grid):
            tentative_g_score = g_score[current] + (
                1 if neighbor[0] == current[0] or neighbor[1] == current[1] else math.sqrt(2)
            )
            if tentative_g_score < g_score.get(neighbor, float('inf')):
                came_from[neighbor] = current
                g_score[neighbor] = tentative_g_score
                f_score[neighbor] = tentative_g_score + Heuristic(neighbor, goal)
                if neighbor not in open_set:
                    open_set.append(neighbor)
    return None

def ClearTerminal():
    # Dual clear terminal
    os.system('cls' if os.name == 'nt' else 'clear')

def DisplayGrid(grid, robotPos=None):
    # Render the grid
    if robotPos:
        x, y = robotPos
        original = grid[y][x]  # Save the original character
        grid[y][x] = '@'
    
    ClearTerminal()
    for row in grid:
        print(''.join(row))
    
    if robotPos:
        grid[y][x] = original  # Restore the original character

def main():
    if len(sys.argv) < 2:
        print("Usage: python pathfinding.py <filePath>")
        sys.exit(1)

    grid_file = sys.argv[1]
    grid = ReadGridFromFile(grid_file)
    start = FindPos(grid, '>')
    goal = FindPos(grid, '*')

    if not start or not goal:
        print("Invalid grid: Missing start (>) or goal (*) position.")
        sys.exit(1)

    path = DestinationSearch(grid, start, goal)
    if path is None:
        print("No path found.")
        return
    elif path:
        for step in path:
            DisplayGrid(grid, step)
            time.sleep(0.7)
        # Robot reached its destination!

    # Mark final position
    DisplayGrid(grid, goal)

if __name__ == "__main__":
    main()

{{< /code >}}

{{< code language="solidity" title="map-data" id="1" expand="Show" collapse="Hide" isCollapsed="false" >}}

##########
#.#.##..*#
#...#..#.#
#.#.#.##.#
#.#....#.#
#.#.##.#.#
#.#..#...#
#.##.###.#
#>#......#
##########

{{< /code >}}

To run this setup, simply do `python path-finding.py map-data`.

---

### Credits -

1. [A* Algorithm](https://www.geeksforgeeks.org/a-search-algorithm/)
2. [Manhattan Distance](https://www.datacamp.com/tutorial/manhattan-distance)
3. [ChatGPT](https://chatgpt.com/)