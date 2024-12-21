# OCS-BERT
Advanced Code Slicing with Pre-Trained Model Fine-Tuned for Open-Source Component Malware Detection

## Introduction
The objective of this project is to develop a system that is capable of detecting malicious components within the open-source Python package index (PyPI).
OCS-BERT leverages taint-based program slicing to isolate sensitive behavior segments and fine-tunes pre-trained model to capture subtle semantic differences across programming languages.

## Prerequisite

### Taint-based program slicing
- jdk19
- [joern-cli](https://docs.joern.io/installation/)

### Fine-tuning
- RTX 4090 GPU (24GB)
- [CodeBERT](https://huggingface.co/microsoft/codebert-base)

## Datasets
Our dataset consists of four parts, with some of them being continuously updated:
1. [Maloss](https://github.com/osssanitizer/maloss/tree/master)
2. [DataDog](https://github.com/DataDog/malicious-software-packages-dataset)
3. [pypi_malregistry](https://github.com/lxyeternal/pypi_malregistry)
4. [Backstabbers](https://dasfreak.github.io/Backstabbers-Knife-Collection)


## Environment Setup
Navigate to the joern-cli directory and create necessary subdirectories.
```
cd joern-cli
mkdir scala
mkdir slice_clean
```
Next, move the files from the scala and scripts directories into the newly created scala folder:
```
sudo crontab -e
```
Then, add the following command to the crontab:
```
*/15 * * * * cd /opt/joern/joern-cli/scala/ && ./crontab.sh >> /opt/joern/joern-cli/scala/cron.log 2>&1
```

## Execution Steps:
Before running the program, please ensure that the following paths are correctly configured:
- Line 31 (`subdirectory`): Fill in the path to the malicious dataset folder.
- `outputFilePath`: Specify the folder where the code slices will be saved.
- `featureFilePath`: Specify the folder where the supplementary feature files will be saved.

Important Note on `findSetupPyFiles` Function:
This function is responsible for locating the relevant files. However, during experiments, we found that different datasets may process components differently, leading to varying paths. You will need to modify or rewrite this function according to your specific dataset structure.


1. First, process process_setup.sc:
This will create code slices for each component in the outputFilePath folder.

2. Afterward, run process_init.sc:
This will append corresponding file names to the outputFilePath folder. Note: Do not run this step multiple times!

3. In Case of Program Crashes:
If the program crashes, check the log to identify the last processed file number.
Update the file number in Line 228 to continue from the point where the program stopped.

```
./joern --script scala/process_setup.sc >  /dev/null
./joern --script scala/process_init.sc
```
