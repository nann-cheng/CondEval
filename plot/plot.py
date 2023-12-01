import matplotlib.pyplot as plt
import numpy as np
import matplotlib.patches as mpatches

# Sample data
categories = ["(80ms, 50Mbit)", "(160ms, 40Mbit)", "(240ms, 30Mbit)"]
group1_bottom = [3, 2, 5]
group1_top = [2, 3, 4]

group2_bottom = [4, 7, 3]
group2_top = [1, 2, 1]

group3_bottom = [2, 3, 4]
group3_top = [3, 2, 3]

group4_bottom = [2, 3, 4]
group4_top = [3, 2, 3]

# Number of categories
n_categories = len(categories)

# Creating a figure and axis
fig, ax = plt.subplots()

# Calculating the width of each bar
bar_width = 0.15

# Setting the position of the bars on the x-axis
r1 = np.arange(n_categories)
r2 = [x + bar_width for x in r1]
r3 = [x + bar_width for x in r2]
r4 = [x + bar_width for x in r3]

# Creating the stacked bars for each group with patterns
ax.bar(r1, group1_bottom, color='blue', width=bar_width, edgecolor='grey', hatch='/', label='computation time')
ax.bar(r1, group1_top, color='blue', width=bar_width, edgecolor='grey', hatch='x', bottom=group1_bottom, label='communication time for')

ax.bar(r2, group2_bottom, color='red', width=bar_width, edgecolor='grey', hatch='/', label='Group 2 Bottom')
ax.bar(r2, group2_top, color='red', width=bar_width, edgecolor='grey', hatch='x', bottom=group2_bottom, label='Group 2 Top')

ax.bar(r3, group3_bottom, color='green', width=bar_width, edgecolor='grey', hatch='/', label='Group 3 Bottom')
ax.bar(r3, group3_top, color='green', width=bar_width, edgecolor='grey', hatch='x', bottom=group3_bottom, label='Group 3 Top')

ax.bar(r4, group4_bottom, color='orange', width=bar_width, edgecolor='grey', hatch='/', label='Group 4 Bottom')
ax.bar(r4, group4_top, color='orange', width=bar_width, edgecolor='grey', hatch='x', bottom=group4_bottom, label='Group 4 Top')

# Adding labels
ax.set_xlabel('Network setting', fontweight='bold')
ax.set_ylabel('Online execution time (ms)', fontweight='bold')
# ax.set_title('Grouped Stacked Bar Chart with Patterns Example')
ax.set_xticks([r + 1.5*bar_width for r in range(n_categories)])
ax.set_xticklabels(categories)


# Creating custom legend entries
legend_elements = [mpatches.Patch(facecolor='blue', edgecolor='grey',  label='$\Pi_{SH2}$'),
                   mpatches.Patch(facecolor='red', edgecolor='grey',  label='Our $\Pi_1$'),
                   mpatches.Patch(facecolor='green', edgecolor='grey',  label='$\Pi_{Mal1}$'),
                   mpatches.Patch(facecolor='orange', edgecolor='grey',  label='Our $\Pi_2$')
                   ]


# Creating legend & showing the plot
first_legend = ax.legend(handles=legend_elements, loc='upper left')
ax.add_artist(first_legend)

# Creating custom legend entries
legend_elements2 = [
                   mpatches.Patch(hatch='/', facecolor='white', edgecolor='grey', label='computation time'),
                   mpatches.Patch(hatch='x', facecolor='white', edgecolor='grey', label='communication time')]

# Creating legend & showing the plot
ax.legend(handles=legend_elements2, loc='upper right')

plt.show()