from distutils.core import setup

setup(
    name = 'mittn',
    packages = ['mittn'],
    version = '0.03',
    description='Mittn security test automation',
    classifiers=[
          "Programming Language :: Python :: 3.4"
    ],
    license='Apache License 2.0',
    author='F-Secure Corporation',
    author_email='opensource@f-secure.com',
    url='https://github.com/praetoria/mittn',
    download_url='https://github.com/praetoria/mittn/tarball/0.03',
    keywords = ['fuzz','fuzzing','security','test','scanner']
    install_requires=open('requirements.txt').readlines(),
)
