# DEP105: importing known typosquatted packages
import colourama  # typosquat of colorama
import requets    # typosquat of requests
from djago import urls  # typosquat of django

# These would be flagged if this is a .py file
data = colourama.Fore.RED
