from setuptools import find_packages, setup

setup(
    name='brewblox-mdns',
    use_scm_version={'local_scheme': lambda v: ''},
    description='mDNS support for BrewBlox systems',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/BrewBlox/brewblox-mdns',
    author='BrewPi',
    author_email='Development@brewpi.com',
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Programming Language :: Python :: 3.8',
        'Intended Audience :: End Users/Desktop',
        'Topic :: System :: Hardware',
    ],
    license='GPLv3',
    keywords='brewing brewpi brewblox embedded plugin service',
    packages=find_packages(exclude=['test', 'docker']),
    install_requires=[
        'brewblox-service',
        'aiozeroconf',
        'async-timeout',
        'click',
    ],
    python_requires='>=3.8',
    setup_requires=['setuptools_scm'],
)
