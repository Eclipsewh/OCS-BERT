# OCS-BERT
Advanced Code Slicing with Pre-Trained Model Fine-Tuned for Open-Source Component Malware Detection

## Prerequisite

### Taint-based program slicing
- jdk19
- [joern-cli](https://docs.joern.io/installation/)

### Fine-tuning
- RTX 4090 GPU (24GB)
- [CodeBERT](https://huggingface.co/microsoft/codebert-base)


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

```
./joern --script scala/process_init.sc
./joern --script scala/process_setup.sc >  /dev/null
```
