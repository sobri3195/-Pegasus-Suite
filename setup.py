from setuptools import setup, find_packages

setup(
    name="Pegasus-Suite",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "requests",
        "colorama",
        "cryptography",
    ],
    entry_points={
        "console_scripts": [
            "pegasus-suite=Pegasus-Suite:main_menu",
        ],
    },
    author="Letda Kes Dr. Sobri, S.Kom.",
    author_email="muhammadsobrimaulana31@gmail.com",
    description="All-in-one cybersecurity toolkit with 1000+ security tools",
    keywords="security, pentest, cybersecurity, hacking, tools",
    url="https://github.com/sobri3195/Pegasus-Suite",
    project_urls={
        "Bug Tracker": "https://github.com/sobri3195/Pegasus-Suite/issues",
        "Documentation": "https://github.com/sobri3195/Pegasus-Suite/README.md",
        "Source Code": "https://github.com/sobri3195/Pegasus-Suite",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
    ],
    python_requires=">=3.6",
) 