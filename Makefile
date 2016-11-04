all:
	find . -type f -print0 | xargs -0 chmod 755
