from setuptools import setup,find_packages

setup(
    name = 'mittn',
    packages = find_packages(),
    version = '0.3.0',
    description='Mittn security test automation',
    classifiers=[
          "Programming Language :: Python :: 3.4"
    ],
    license='Apache License 2.0',
    author='F-Secure Corporation',
    author_email='opensource@f-secure.com',
    url='https://github.com/praetoria/mittn',
    download_url='https://github.com/praetoria/mittn/tarball/0.3.0',
    keywords = ['fuzz','fuzzing','security','test','scanner'],
    install_requires=['pytz',
        'python-dateutil',
        'sqlalchemy',
        'requests']
)
