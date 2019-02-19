# -*- coding: utf-8 -*-


from setuptools import setup, find_packages


setup(
    name='s54http',
    version='1.0.0',
    license='http://www.apache.org/licenses/LICENSE-2.0',
    description='socks5 proxy',
    packages=find_packages(),
    install_requires=[
        'cryptography',
        'pycrypto',
        'pyOpenSSL',
        'service-identity',
        'Twisted',
    ],
    python_requires=">=3.6",
    entry_points={
        'console_scripts': [
            's5pproxy = s54http.proxy:main',
            's5pserver = s54http.server:main',
        ]
    }
)
