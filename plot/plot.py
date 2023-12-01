import matplotlib.pyplot as plt
import numpy as np

# Sample data
categories = ["Category A", "Category B", "Category C"]
group1 = [3, 2, 5]
group2 = [4, 7, 3]
group3 = [2, 3, 4]

# Number of categories
n_categories = len(categories)

# Creating a figure and axis
fig, ax = plt.subplots()

# Calculating the width of each bar
bar_width = 0.3

# Setting the position of the bars on the x-axis
r1 = np.arange(n_categories)
r2 = [x + bar_width for x in r1]
r3 = [x + bar_width for x in r2]

# Creating the bars with different hatching
ax.bar(
    r1,
    group1,
    color="grey",
    width=bar_width,
    edgecolor="grey",
    hatch="/",
    label="Group 1",
)
ax.bar(
    r2,
    group2,
    color="grey",
    width=bar_width,
    edgecolor="grey",
    hatch="\\",
    label="Group 2",
)
ax.bar(
    r3,
    group3,
    color="grey",
    width=bar_width,
    edgecolor="grey",
    hatch="-",
    label="Group 3",
)

# Adding labels
ax.set_xlabel("Categories", fontweight="bold")
ax.set_ylabel("Values", fontweight="bold")
ax.set_title("Grouped Bar Chart with Hatching Example")
ax.set_xticks([r + bar_width for r in range(n_categories)])
ax.set_xticklabels(categories)

# Creating legend & showing the plot
ax.legend()
plt.show()
