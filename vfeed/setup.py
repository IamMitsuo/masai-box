from setuptools import setup

setup(name='vfeed',
	version='0.7.2.1',
	packages=['vfeed', 
			'vfeed/config', 
			'vfeed/lib',
			'vfeed/lib/common',
			'vfeed/lib/core',
			'vfeed/lib/core/methods',
			'vfeed/lib/migration'],
	package_data={'vfeed': ['vfeed.db']})
	
