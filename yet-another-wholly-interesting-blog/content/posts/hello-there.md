+++
date = '2026-01-18T23:54:51Z'
draft = false
title = 'A very basic Malware analysis Machine Learning project'
+++

# Background

This year, 2026 to alleviate any doubt, I have set myself the ambition to focus on tangibly improving at Machine Learning and Reverse Engineering. Both are topics i've studied in my career and during my university degree. However I feel like I do not have as much knowledge of as I would like.

Unfortunately with anything unless you're constantly exercising with an aim to improve and deepen your abilities at best you stagnate, at worst the knowledge slowly starts fading away. So how can I achieve this and where can I start?


## A flawed but achievable plan

As a habitual hoarder of ebooks on both topics from past Humble Bundle deals I can easily kick things off with targeting reading material. But it’s not entirely a great revelation that learning can be really solidified by practical implementation of concepts into a project rather than just learning theory alone. So here is the plan, for each month in 2026 I want to read two books (or complete a course) and work on a project. 

For January this is:  
    
- Evasive Malware: A Field Guide to Detecting, Analyzing, and Defeating Advanced Threats by Kyle Cucci
    
- Google Machine Learning Crash Course https://developers.google.com/machine-learning/crash-course
    
- Training a simple model performing classification using a Kaggle malware dataset https://www.kaggle.com/datasets/greenwarbler/malware-benignpe-files?select=Malware-Benign.csv which then I can use to test any window binary to see if it can classify as benign or malicious.  

## The Book - Evasive Malware

I'm on the last chapter of this book now and so far it's been a fantastic bridge between content like SANS 610 which is very much setting you up with the tools and understanding of what is needed and a course like Zero-2-Automated which the content largely focuses on individual malware families and how to go about tackling them. The missing gap I found was a broad description of anti analysis techniques that are commonly used with examples of how they worked. Evasive Malware has been doing a great job at introducing to all these anti analysis techniques and way to get around them. I've had at least two Aha moments which explained where a particularly stubborn sample got the better of me in the past when the debugger kept throwing a wobbly. I can certainly recommend this, it's not designed an entry point, pardon the pun. But I've taken a great deal from the first 13 chapters I've read.

## The Course - Google Machine Learning Crash Course

A similar story as with the book I've been reading this course has provided a fantastic gap closer on quite a lot of the basic Machine Learning theory such as Calculating Loss. One aspect of Machine Learning I felt was always holding me back was not taking time to understand some of the underlying maths. Especially from a programming background it's too easy to get carried away with python libraries and skip the important theory. This course whilst I'm sure is barely a drop in the ocean so far has been incredibly rewarding to work through to better understand the subject better.

## The project

My goal was to take a dataset based malware analysis, train a simple model then be able to export this into a python program and actually test the model in my FLAREVM sandbox against malicious binaries. The purpose isn't some sort of enterprise grade Machine Learning malware analysis software. But to complete a small project end to end and importantly discover the caveats, issues and shortcomings of my approach along the way. From my 10+ years in Software & Cybersecurity if i've learned anything it's that the breakthroughs in knowledge always are accomplished after trying something and failing.

### The Dataset

https://www.kaggle.com/datasets/greenwarbler/malware-benignpe-files?select=Malware-Benign.csv

"This dataset is designed for malware detection research using machine learning techniques and is based on static analysis of Microsoft Windows Portable Executable (PE) files.

The data consists of 79 numerical features extracted from different structural components of PE files, including various headers and sections defined in the official Windows PE format specification. These features represent low-level metadata and structural characteristics of executable files and are commonly used in academic and industrial malware analysis.

Each sample in the dataset corresponds to a single Windows executable file, labeled as either malicious or benign, making the dataset suitable for binary classification tasks."

https://learn.microsoft.com/en-us/windows/win32/debug/pe-format

This dataset does not redefine or modify any PE fields; it strictly follows the official specification provided by Microsoft.

### Exploratory Data Analysis

So we have a dataset of PE numerical features based on components of a PE file. Lets take a look at the breakdown of how many are labelled as malware vs benign? Lets load it up and see what we've got.

```Python {linenos=inline codeFences=false}
import pandas as pd
df = pd.read_csv('Malware-Benign.csv')
print(df['Malware'].value_counts())
```

Turns out the dataset is skewed to having more malicious examples than benign. This is somewhat surprising considered it's a real  dataset that Microsoft has put together, we could look at ways to fix this like under sampling but because the ratio isn't really strongly skewed it would just be dropping a lot of potentially useful training data. 

Malware  
1 -    14599   
0 -    5012  

Next up we split into a 70% 30% Train test. I'm not angling this article as an intro to Machine Learning tutorial so I'll keep the details light as to why. I will however draw attention to stratify=y which is taking the y variable defined at df['mMlware'] and ensuring we don't end up with all of the malware = 0 randomly in either the train or test dataset. Which would make the model very sad. 
 
```Python {linenos=inline}
from sklearn.model_selection import train_test_split
# Separate features (X) and target (y)
X = df.drop('Malware', axis=1)
y = df['Malware']

# Split with stratification ensures that the training and testing sets have the same proportion of classes (or labels) as the original dataset.
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, stratify=y, random_state=42)

print(f"Training set shape: {X_train.shape}")
print(f"Test set shape: {X_test.shape}")
```

Here we have the successfully split data shapes:  

|Set Type|Result|
|-|-|
|Training set shape|(13727, 78)|  
|Test set shape|(5884, 78)|

Because it wouldn't be a ML article without a boxplot sneaking itself in somewhere lets now take a look at how a single field or feature relates to whether the sample is malware or benign:

```Python {linenos=inline}
import matplotlib.pyplot as plt
import seaborn as sns
# 1. Create a temporary DataFrame that brings X and y back together for plotting
plot_data = X_train.copy()
plot_data['Malware'] = y_train

plt.figure(figsize=(15, 6))
# 2. Create the Box Plot on the left of suspicious import functions
plt.subplot(1, 2, 1)
sns.boxplot(x='Malware', y='SuspiciousImportFunctions', data=plot_data)
plt.title('Box Plot of Section SuspiciousImportFunctions')
# 3. Create the Distribution Plot on the right of suspicious import functions
plt.subplot(1, 2, 2)
sns.histplot(data=plot_data, x='SuspiciousImportFunctions', hue='Malware', kde=True, element="step")
plt.title('Distribution of Section SuspiciousImportFunctions')
plt.show()
```

Rather unsurprisingly we see a correlation between number of suspicious import functions and a sample being malware! We could in theory stop here and call it a day making the assessment if a file ha more than X number of Suspicious Import functions it't malware. But hopefully we can see immediate flaws in that, really we want to use many more data points to make a more accurate determination..

![Resize](/images/image.png?width=200px)  

So to do that lets take the top most and bottom most corresponding correlations for all of the available features and see what bubbles up to the top or sinks to the bottom. These will hopefully be features that can be used to correlate strongly in combination with each other to determine the maliciousness of a file.

```Python {linenos=inline}
# 1. Create a new dataframe with ONLY numeric columns
numeric_X_train = X_train.select_dtypes(include=['number'])
# 2. Calculate correlations on that numeric data
correlations = numeric_X_train.corrwith(y_train).sort_values(ascending=False)
# 3. Show the strongest positive and negative correlations
print("--- Top Positive Correlations (Indicates Malware) ---")
print(correlations.head(15))

print("\n--- Top Negative Correlations (Indicates Benign) ---")
print(correlations.tail(10))
```

--- Top Positive Correlations (Indicates Malware) ---  
SectionMaxChar               0.399776  
SizeOfStackReserve           0.247231  
SuspiciousImportFunctions    0.215623  
DllCharacteristics           0.196971  
e_maxalloc                   0.190034  
FileAlignment                0.168689  
MinorLinkerVersion           0.145703  
CheckSum                     0.136488  
NumberOfSections             0.113213  
SectionsLength               0.113145  
SizeOfHeapReserve            0.085310  
e_lfanew                     0.081512  
SuspiciousNameSection        0.057701  
SectionMaxPointerData        0.045652  
e_oeminfo                    0.043394  

--- Top Negative Correlations (Indicates Benign) ---  
Subsystem               -0.498877  
MajorSubsystemVersion   -0.604873. 
e_magic                       NaN  
SectionMaxEntropy             NaN  
SectionMaxRawsize             NaN  
SectionMaxVirtualsize         NaN  
SectionMinPhysical            NaN   
SectionMinVirtual             NaN  
SectionMinPointerData         NaN   
SectionMainChar               NaN  

### The Importance of Feature Selection

As we can see quite a few values came back with NaN (Not a Number). Unfortunately we have some fields where every single value is 0 like SectionMaxEntropy and SectionMaxRawsize, these can be dropped as they will not add any value.

In other cases like e_magic this is because every valid PE file starts with the same magic bytes (0x5A4D). Since the value never changes, therefore can also be dropped. Having an understanding of your data is really paramount to getting a good result.

We have also some very strong features but they potentially could be leading us astray.. Let's have a ponder about what some these features actually represent:

**The Problem Children:**
- `MinorOperatingSystemVersion`: Older required OS version
- `MajorOperatingSystemVersion`: Older required OS version  
- `TimeDateStamp`: When the file was compiled

These features are highly correlated with malware in this dataset, but ** all for the wrong reasons**. The dataset likely contains older malware samples that naturally targeted older Windows versions common at the time. The model is learning "old = malicious" rather than actual malicious behavior. This is why feature selection is such an important step as the old Garbage in Garbage out adage goes.

Not to put too fine a point on the matter but if I deployed this model:  

- Modern malware targeting Windows 11 > Classified as benign
- Legitimate old software > Classified as malware

**Solutionising:**

So what I ended up doing was retraining the model after removing these temporal features:

```python
# Remove features that create temporal bias
cols_to_drop = ['MinorOperatingSystemVersion', 
                'MajorOperatingSystemVersion', 
                'TimeDateStamp']
X_train_refined = numeric_X_train.drop(columns=cols_to_drop, errors='ignore')
X_test_refined = numeric_X_test.drop(columns=cols_to_drop, errors='ignore')

# Retrain on more robust features
rfc_refined = RandomForestClassifier(random_state=42)
rfc_refined.fit(X_train_refined, y_train)
```

High feature importance doesn't automatically mean good features. It's super important to consider: "Is this correlation meaningful, or is it a dataset artifact?" This is where combining ML knowledge with malware analysis expertise becomes essential.

### Training Random Forest

I've decided to use Random Forest as a Classifier. Largely due to having some familiarity with it and it being a simple effective "white box" model which we can interrogate the weights of the parameters to understand the results we are getting. The theory behind the classifier is going beyond the scope of this article but to put it simply Random Forest is an "ensemble method" which randomly splits up subsets of features and generates trees based on those subsets then aggregates the multiple outputs into a single result. They can be used for regression or classification problems, the latter is what we are attempting to achieve. 

Where as a decision tree is a chain of if/else statements, Random Forest is less susceptible to over fitting since essentially rather than end up with a structure that perfectly fits your training data like in a Decision Tree the random forests random nature helps generalize the model. So it may be worse at predicting the Training Set it should be better with the Test set and real life data.

```Python {linenos=inline}
from sklearn.ensemble import RandomForestClassifier

# 1. Initialize the model
# random_state=42 helps ensure we get the same results if we run this again
# I picked some hyper params, if this was a real project we could tweak these to get a better result
rfc = RandomForestClassifier(
    n_estimators=500,
    max_depth=30,
    min_samples_split=10,
    class_weight='balanced',
    random_state=42
)

# 2. Fit (train) the model
print("Training the model...")
rfc.fit(numeric_X_train, y_train)
print("Training complete!")

numeric_X_test = X_test.select_dtypes(include=['number'])

# Ensure exact same columns in exact same order
numeric_X_test = X_test[numeric_X_train.columns]

# Generate predictions
y_pred = rfc.predict(numeric_X_test)

print("Predictions generated!")
```

### Analysing the training results

```Python {linenos=inline}
from sklearn.metrics import confusion_matrix
# 1. Calculate the matrix
cm = confusion_matrix(y_test, y_pred)
# 2. Plotting as a heatmap
plt.figure(figsize=(8, 6))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=['Predicted Benign', 'Predicted Malware'],
            yticklabels=['Actual Benign', 'Actual Malware'])
plt.ylabel('Actual')
plt.xlabel('Predicted')
plt.title('Confusion Matrix')
plt.show()
```

![Image](/images/confusion.png?width=400px)  

An excellent result, lets wrap up there and pat ourselves on the back not worrying about if it works in "production".

One of the biggest bug bears of Cybersecurity Analysts, which is especially true with any black box machine learning is not being able to determine what features actually lead a detection to firing. Vendors often hand wave this away, but having never worked in or with a SOC where the True Positive percentage is higher than False Positive / Benign Positive I think it's more than fair for an analyst to want to understand why a detection mechanism thinks something is malicious. 

Not all types of machine learning can do this Neural Networks from my understanding are pretty impenetrable. But in this case we can look at the importance per feature to try to understand what features are pushing the model to a decision. 

```Python {linenos=inline}
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
# 1. Get the importance scores from the trained model
importances = rfc.feature_importances_
# 2. Create a DataFrame to map scores to column names
# We use numeric_X_train.columns to ensure we match the right names
feature_importance_df = pd.DataFrame({
    'Feature': numeric_X_train.columns,
    'Importance': importances
})

# 3. Sort by importance (highest on top)
feature_importance_df = feature_importance_df.sort_values(by='Importance', ascending=False)

# 4. Display the Top 10 as a table
print("--- Top 10 Most Important Features ---")
print(feature_importance_df.head(10))

# 5. Visualise the Top 10
plt.figure(figsize=(10, 6))
sns.barplot(x='Importance', y='Feature', data=feature_importance_df.head(10))
plt.title('Top 10 Features for Malware Detection')
plt.show()
```

--- Top 10 Most Important Features ---  
                        Feature  Importance  
36  MinorOperatingSystemVersion    0.090196  
25           MajorLinkerVersion    0.085131  
39        MajorSubsystemVersion    0.084642  
46           SizeOfStackReserve    0.073966  
19                TimeDateStamp    0.061142  
32                    ImageBase    0.057009  
23              Characteristics    0.055775  
35  MajorOperatingSystemVersion    0.046653  
44                    Subsystem    0.044585  
40        MinorSubsystemVersion    0.037700  

![Image](/images/top10feature.png?width=400px)  

Interesting, it turns out that three of the most important features are all version based. This is where domain knowledge comes in very handy and hopefully my plan to develop meaningful skill and knowledge in both ML and Malware analysis will start to produce some value. Often malware authors really want to ensure that they can infect older systems. If we refer to window documentation we see:

**MinorOperatingSystemVersion - The minor version number of the required operating system.**

So we could draw the conclusion that malware often uses  older MinorOperatingSystemVersion requirements to target old versions of windows. However this could also be that the dataset just had a lot of old malware samples in it rather than modern ones. This is where having a dataset you know exactly what each sample's providence is greatly will increase your ability to get more accurate results.

The other value to pick out is TimeDateStamp which is when the file was created potentially supporting the hypothesis that the malware samples are older? Either way before moving onto the next step I actually removed some of these feature and re-trained the model on a smaller subset of features which I was confident would lead to more TP results. 

### Operationalisation (kinda)

One major issue highlighted during the Operationalization phase is "Training-Serving Skew". The Kaggle dataset contains derived features like SuspiciousImportFunctions, but because it's a "black box" dataset, we unfortunately don't have the source code for how that count was calculated.

In my  script, I had to approximate this feature by compiling my own list of suspicious API calls. If the dataset creator used a different list (or different matching logic), my script's '5 suspicious imports' might mean something totally different to the model than the dataset's '5 suspicious imports.'

This is a critical limitation of using pre-computed datasets for end-to-end projects. I plan to fix this by generating my own dataset from scratch. For now, however, we will suspend disbelief and assume my list approximates theirs closely enough to function.

That being said this is probably the step i've really never reached before when doing ML projects. Up to this point the whole ML process is mostly academic in nature. It's interesting to know this model can accurately catch X% of malware samples from the original training data but can it be:

a) turned into something useful  
b) actually work with real world data and use cases

So this next python script is attempting to do just that. We are using the pefile library to extract features from an actual executable passed to it with command line arguments. The next important step is we need to extract the same features the model was trained on which in our case means also calculating the files entropy.

Needless to say this isn't the first script I wrote to do this the start was very hacky and just about worked. Since then it's been iterated on to make it actually work properly and to make it more readable using our good friend Claude.

```Python {linenos=inline}
#!/usr/bin/env python3
"""
PE Malware Detection Script
Extracts 74 features required by the trained model

Note: The model was trained WITHOUT temporal features (OS versions, TimeDateStamp)
to prevent temporal bias. While these show high correlation in the dataset, they
represent when malware was created rather than inherent malicious characteristics.

Feature Categories:
1. DOS_HEADER (17 features) - Legacy DOS compatibility header
2. FILE_HEADER (6 features) - COFF file header
3. OPTIONAL_HEADER (24 features) - PE-specific header
4. Section Statistics (15 features) - Calculated from section table
5. Behavioral Analysis (2 features) - Suspicious patterns
6. Directory Entries (8 features) - Data directory presence/size
7. Missing OPTIONAL_HEADER (2 features) - Magic number
"""

import sys
import os
import pickle
import pefile
import pandas as pd
import numpy as np
import warnings
from typing import Dict, Tuple, Optional, List

# Suppress warnings
warnings.filterwarnings("ignore")

# ============================================================================
# SUSPICIOUS INDICATORS
# ============================================================================

SUSPICIOUS_IMPORTS = {
    # Process manipulation
    'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect', 'VirtualProtectEx',
    'WriteProcessMemory', 'ReadProcessMemory', 'CreateRemoteThread',
    'OpenProcess', 'TerminateProcess', 'GetProcAddress', 'LoadLibraryA',
    'LoadLibraryW', 'LoadLibraryExA', 'LoadLibraryExW',
    
    # Code injection
    'NtQueueApcThread', 'QueueUserAPC', 'SetWindowsHookEx', 'RtlCreateUserThread',
    'NtCreateThreadEx', 'CreateThread', 'ResumeThread', 'SuspendThread',
    
    # Memory manipulation
    'RtlMoveMemory', 'memcpy', 'NtWriteVirtualMemory', 'NtReadVirtualMemory',
    'NtAllocateVirtualMemory', 'NtProtectVirtualMemory',
    
    # Debugging/Anti-analysis
    'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess',
    'OutputDebugStringA', 'OutputDebugStringW', 'DebugActiveProcess',
    
    # Registry manipulation
    'RegOpenKeyExA', 'RegOpenKeyExW', 'RegSetValueExA', 'RegSetValueExW',
    'RegCreateKeyExA', 'RegCreateKeyExW', 'RegDeleteKeyA', 'RegDeleteKeyW',
    
    # File operations
    'CreateFileA', 'CreateFileW', 'WriteFile', 'ReadFile', 'DeleteFileA',
    'DeleteFileW', 'MoveFileA', 'MoveFileW', 'CopyFileA', 'CopyFileW',
    
    # Network operations
    'WSAStartup', 'socket', 'connect', 'send', 'recv', 'InternetOpenA',
    'InternetOpenW', 'InternetOpenUrlA', 'InternetOpenUrlW', 'HttpSendRequestA',
    'HttpSendRequestW', 'URLDownloadToFileA', 'URLDownloadToFileW',
    
    # Cryptography
    'CryptEncrypt', 'CryptDecrypt', 'CryptAcquireContextA', 'CryptAcquireContextW',
    'CryptCreateHash', 'CryptHashData', 'CryptDeriveKey',
    
    # Privilege escalation
    'AdjustTokenPrivileges', 'OpenProcessToken', 'LookupPrivilegeValueA',
    'LookupPrivilegeValueW', 'ImpersonateLoggedOnUser',
    
    # Service manipulation
    'CreateServiceA', 'CreateServiceW', 'OpenServiceA', 'OpenServiceW',
    'StartServiceA', 'StartServiceW', 'ControlService', 'DeleteService',
    
    # Keylogging
    'GetAsyncKeyState', 'GetKeyState', 'GetForegroundWindow', 'SetWindowsHookExA',
    'SetWindowsHookExW', 'CallNextHookEx',
    
    # Evasion
    'Sleep', 'GetTickCount', 'GetSystemTime', 'GetLocalTime',
}

SUSPICIOUS_SECTION_NAMES = {
    '.upx', 'upx0', 'upx1', 'upx2',  # UPX packer
    '.aspack', '.adata', '.asdata',  # ASPack packer
    '.petite', '.pec1', '.pec2',     # PEtite packer
    '.neolite',                       # Neolite packer
    '.themida', '.winlicense',        # Themida/Winlicense
    '.vmprotect',                     # VMProtect
    '.mpress',                        # MPRESS
    '.packed', '.pdata',              # Generic packed indicators
    'text', 'CODE', 'DATA',           # Non-standard naming (missing dot)
}


# ============================================================================
# RESOURCE LOADING
# ============================================================================

def load_resources() -> Tuple[object, List[str]]:
    """
    Load the trained model and the column list.
    
    Returns:
        Tuple of (model, columns list)
    
    Raises:
        FileNotFoundError: If model files are missing
        Exception: If model files are corrupted
    """
    try:
        base_path = os.path.dirname(os.path.abspath(__file__))
        
        model_path = os.path.join(base_path, 'malware_detector.pkl')
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model file not found: {model_path}")
            
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
            
        columns_path = os.path.join(base_path, 'model_columns.pkl')
        if not os.path.exists(columns_path):
            raise FileNotFoundError(f"Columns file not found: {columns_path}")
            
        with open(columns_path, 'rb') as f:
            columns = pickle.load(f)
        
        # Validate model has required methods
        if not hasattr(model, 'predict') or not hasattr(model, 'predict_proba'):
            raise ValueError("Loaded object is not a valid classifier model")
            
        if not hasattr(model, 'feature_importances_'):
            print("Warning: Model does not have feature_importances_ attribute")
            
        print(f"[+] Loaded model expecting {len(columns)} features")
        return model, columns
        
    except FileNotFoundError as e:
        print(f"[!] Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error loading model files: {e}")
        sys.exit(1)


# ============================================================================
# CATEGORY 1: DOS_HEADER EXTRACTION (17 features)
# ============================================================================

def extract_dos_header(pe: pefile.PE) -> Dict[str, int]:
    """
    Extract DOS header features (e_* fields).
    
    The DOS header is a legacy structure from MS-DOS compatibility.
    Malware often manipulates these fields for evasion.
    
    Args:
        pe: pefile.PE object
        
    Returns:
        Dictionary with 17 DOS header features
    """
    dos = {}
    
    if hasattr(pe, 'DOS_HEADER'):
        dh = pe.DOS_HEADER
        
        dos['e_magic'] = dh.e_magic          # Magic number (should be 0x5A4D = "MZ")
        dos['e_cblp'] = dh.e_cblp            # Bytes on last page of file
        dos['e_cp'] = dh.e_cp                # Pages in file
        dos['e_crlc'] = dh.e_crlc            # Relocations
        dos['e_cparhdr'] = dh.e_cparhdr      # Size of header in paragraphs
        dos['e_minalloc'] = dh.e_minalloc    # Minimum extra paragraphs needed
        dos['e_maxalloc'] = dh.e_maxalloc    # Maximum extra paragraphs needed
        dos['e_ss'] = dh.e_ss                # Initial (relative) SS value
        dos['e_sp'] = dh.e_sp                # Initial SP value
        dos['e_csum'] = dh.e_csum            # Checksum
        dos['e_ip'] = dh.e_ip                # Initial IP value
        dos['e_cs'] = dh.e_cs                # Initial (relative) CS value
        dos['e_lfarlc'] = dh.e_lfarlc        # File address of relocation table
        dos['e_ovno'] = dh.e_ovno            # Overlay number
        dos['e_oemid'] = dh.e_oemid          # OEM identifier
        dos['e_oeminfo'] = dh.e_oeminfo      # OEM information
        dos['e_lfanew'] = dh.e_lfanew        # File address of new exe header (PE header offset)
    
    return dos


# ============================================================================
# CATEGORY 2: FILE_HEADER EXTRACTION (6 features)
# ============================================================================

def extract_file_header(pe: pefile.PE) -> Dict[str, int]:
    """
    Extract COFF file header features.
    
    The FILE_HEADER contains critical metadata about the PE file structure.
    
    Args:
        pe: pefile.PE object
        
    Returns:
        Dictionary with 6 FILE_HEADER features
    """
    fh = {}
    
    if hasattr(pe, 'FILE_HEADER'):
        file_hdr = pe.FILE_HEADER
        
        # Machine type (e.g., 0x14c = x86, 0x8664 = x64)
        fh['Machine'] = file_hdr.Machine
        
        # Number of sections in the file
        fh['NumberOfSections'] = file_hdr.NumberOfSections
        
        # Pointer to COFF symbol table (usually 0 for executables)
        fh['PointerToSymbolTable'] = file_hdr.PointerToSymbolTable
        
        # Number of entries in symbol table
        fh['NumberOfSymbols'] = file_hdr.NumberOfSymbols
        
        # Size of optional header
        fh['SizeOfOptionalHeader'] = file_hdr.SizeOfOptionalHeader
        
        # File characteristics (flags like executable, DLL, etc.)
        # Common flags: 0x0002 = EXECUTABLE_IMAGE, 0x2000 = DLL
        fh['Characteristics'] = file_hdr.Characteristics
    
    return fh


# ============================================================================
# CATEGORY 3: OPTIONAL_HEADER EXTRACTION (24 features)
# ============================================================================

def extract_optional_header(pe: pefile.PE) -> Dict[str, int]:
    """
    Extract OPTIONAL_HEADER features.
    
    Despite the name, this header is mandatory for executables.
    Contains crucial information about how to load and execute the PE.
    
    Args:
        pe: pefile.PE object
        
    Returns:
        Dictionary with 26 OPTIONAL_HEADER features (including Magic)
    """
    opt = {}
    
    if hasattr(pe, 'OPTIONAL_HEADER'):
        oh = pe.OPTIONAL_HEADER
        
        # Magic number (0x10b = PE32, 0x20b = PE32+/64-bit)
        opt['Magic'] = oh.Magic
        
        # Linker version
        opt['MajorLinkerVersion'] = oh.MajorLinkerVersion
        opt['MinorLinkerVersion'] = oh.MinorLinkerVersion
        
        # Code and data sizes
        opt['SizeOfCode'] = oh.SizeOfCode
        opt['SizeOfInitializedData'] = oh.SizeOfInitializedData
        opt['SizeOfUninitializedData'] = oh.SizeOfUninitializedData
        
        # Entry point RVA (Relative Virtual Address)
        opt['AddressOfEntryPoint'] = oh.AddressOfEntryPoint
        
        # Base addresses
        opt['BaseOfCode'] = oh.BaseOfCode
        opt['ImageBase'] = oh.ImageBase
        
        # Alignment values
        opt['SectionAlignment'] = oh.SectionAlignment  # In memory
        opt['FileAlignment'] = oh.FileAlignment        # On disk
        
        # Version information
        opt['MajorImageVersion'] = oh.MajorImageVersion
        opt['MinorImageVersion'] = oh.MinorImageVersion
        opt['MajorSubsystemVersion'] = oh.MajorSubsystemVersion
        opt['MinorSubsystemVersion'] = oh.MinorSubsystemVersion
        
        # Image sizes
        opt['SizeOfHeaders'] = oh.SizeOfHeaders
        opt['CheckSum'] = oh.CheckSum
        opt['SizeOfImage'] = oh.SizeOfImage
        
        # Subsystem (3 = Console, 2 = GUI, etc.)
        opt['Subsystem'] = oh.Subsystem
        
        # DLL characteristics (ASLR, DEP, etc.)
        opt['DllCharacteristics'] = oh.DllCharacteristics
        
        # Stack and heap sizes
        opt['SizeOfStackReserve'] = oh.SizeOfStackReserve
        opt['SizeOfStackCommit'] = oh.SizeOfStackCommit
        opt['SizeOfHeapReserve'] = oh.SizeOfHeapReserve
        opt['SizeOfHeapCommit'] = oh.SizeOfHeapCommit
        
        # Loader flags (obsolete but may be set)
        opt['LoaderFlags'] = oh.LoaderFlags
        
        # Number of data directories
        opt['NumberOfRvaAndSizes'] = oh.NumberOfRvaAndSizes
    
    return opt


# ============================================================================
# CATEGORY 4: SECTION STATISTICS (15 features)
# ============================================================================

def extract_section_statistics(pe: pefile.PE) -> Dict[str, float]:
    """
    Calculate statistical features from PE sections.
    
    Sections contain code, data, resources, etc. Unusual section
    characteristics often indicate packing or malicious modifications.
    
    Args:
        pe: pefile.PE object
        
    Returns:
        Dictionary with 15 section-related features
    """
    sections = {}
    
    if not hasattr(pe, 'sections') or len(pe.sections) == 0:
        # No sections - highly unusual, fill with zeros
        sections['SectionsLength'] = 0
        sections['SectionMinEntropy'] = 0
        sections['SectionMaxEntropy'] = 0
        sections['SectionMinRawsize'] = 0
        sections['SectionMaxRawsize'] = 0
        sections['SectionMinVirtualsize'] = 0
        sections['SectionMaxVirtualsize'] = 0
        sections['SectionMaxPhysical'] = 0
        sections['SectionMinPhysical'] = 0
        sections['SectionMaxVirtual'] = 0
        sections['SectionMinVirtual'] = 0
        sections['SectionMaxPointerData'] = 0
        sections['SectionMinPointerData'] = 0
        sections['SectionMaxChar'] = 0
        sections['SectionMainChar'] = 0
        return sections
    
    # Collect section metrics
    entropies = []
    raw_sizes = []
    virtual_sizes = []
    physical_addresses = []
    virtual_addresses = []
    pointer_to_raw_data = []
    characteristics = []
    
    for section in pe.sections:
        # Entropy (high entropy = encrypted/packed)
        entropies.append(section.get_entropy())
        
        # Raw size (on disk)
        raw_sizes.append(section.SizeOfRawData)
        
        # Virtual size (in memory)
        virtual_sizes.append(section.Misc_VirtualSize)
        
        # Physical address (deprecated but sometimes set)
        if hasattr(section, 'Misc_PhysicalAddress'):
            physical_addresses.append(section.Misc_PhysicalAddress)
        else:
            physical_addresses.append(0)
        
        # Virtual address (RVA where section is loaded)
        virtual_addresses.append(section.VirtualAddress)
        
        # Pointer to raw data (file offset)
        pointer_to_raw_data.append(section.PointerToRawData)
        
        # Characteristics (flags: readable, writable, executable, etc.)
        characteristics.append(section.Characteristics)
    
    # Calculate statistics
    sections['SectionsLength'] = len(pe.sections)
    
    # Entropy statistics
    sections['SectionMinEntropy'] = min(entropies) if entropies else 0
    sections['SectionMaxEntropy'] = max(entropies) if entropies else 0
    
    # Size statistics
    sections['SectionMinRawsize'] = min(raw_sizes) if raw_sizes else 0
    sections['SectionMaxRawsize'] = max(raw_sizes) if raw_sizes else 0
    sections['SectionMinVirtualsize'] = min(virtual_sizes) if virtual_sizes else 0
    sections['SectionMaxVirtualsize'] = max(virtual_sizes) if virtual_sizes else 0
    
    # Physical address statistics
    sections['SectionMaxPhysical'] = max(physical_addresses) if physical_addresses else 0
    sections['SectionMinPhysical'] = min(physical_addresses) if physical_addresses else 0
    
    # Virtual address statistics
    sections['SectionMaxVirtual'] = max(virtual_addresses) if virtual_addresses else 0
    sections['SectionMinVirtual'] = min(virtual_addresses) if virtual_addresses else 0
    
    # Pointer to raw data statistics
    sections['SectionMaxPointerData'] = max(pointer_to_raw_data) if pointer_to_raw_data else 0
    sections['SectionMinPointerData'] = min(pointer_to_raw_data) if pointer_to_raw_data else 0
    
    # Characteristics statistics
    sections['SectionMaxChar'] = max(characteristics) if characteristics else 0
    # Note: SectionMainChar likely means "most common characteristics"
    # Using the first section's characteristics as heuristic
    sections['SectionMainChar'] = characteristics[0] if characteristics else 0
    
    return sections


# ============================================================================
# CATEGORY 5: BEHAVIORAL ANALYSIS (2 features)
# ============================================================================

def extract_behavioral_features(pe: pefile.PE) -> Dict[str, int]:
    """
    Analyze behavioral indicators of maliciousness.
    
    These features look for suspicious patterns in imports and section names
    that are common in malware.
    
    Args:
        pe: pefile.PE object
        
    Returns:
        Dictionary with 2 behavioral features
    """
    behavioral = {}
    
    # Feature 1: Count suspicious import functions
    suspicious_import_count = 0
    
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    # Decode bytes to string if necessary
                    import_name = imp.name.decode('utf-8') if isinstance(imp.name, bytes) else imp.name
                    if import_name in SUSPICIOUS_IMPORTS:
                        suspicious_import_count += 1
    
    behavioral['SuspiciousImportFunctions'] = suspicious_import_count
    
    # Feature 2: Check for suspicious section names
    suspicious_section_count = 0
    
    if hasattr(pe, 'sections'):
        for section in pe.sections:
            # Get section name and clean it
            section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00').lower()
            
            # Check against known packer/suspicious names
            if section_name in SUSPICIOUS_SECTION_NAMES:
                suspicious_section_count += 1
            
            # Also check for sections without leading dot (non-standard)
            if section_name and not section_name.startswith('.'):
                suspicious_section_count += 1
    
    behavioral['SuspiciousNameSection'] = suspicious_section_count
    
    return behavioral


# ============================================================================
# CATEGORY 6: DIRECTORY ENTRIES (8 features)
# ============================================================================

def extract_directory_entries(pe: pefile.PE) -> Dict[str, int]:
    """
    Extract data directory presence and size information.
    
    Data directories point to important structures like imports, exports,
    resources, etc. Their presence and size can indicate malicious behavior.
    
    Args:
        pe: pefile.PE object
        
    Returns:
        Dictionary with 8 directory entry features
    """
    directories = {}
    
    # Initialize all to 0
    directories['DirectoryEntryImport'] = 0
    directories['DirectoryEntryImportSize'] = 0
    directories['DirectoryEntryExport'] = 0
    directories['ImageDirectoryEntryExport'] = 0
    directories['ImageDirectoryEntryImport'] = 0
    directories['ImageDirectoryEntryResource'] = 0
    directories['ImageDirectoryEntryException'] = 0
    directories['ImageDirectoryEntrySecurity'] = 0
    
    if not hasattr(pe, 'OPTIONAL_HEADER'):
        return directories
    
    # Check if DATA_DIRECTORY exists
    if not hasattr(pe.OPTIONAL_HEADER, 'DATA_DIRECTORY'):
        return directories
    
    # Data directory indices (from PE specification)
    # 0 = Export, 1 = Import, 2 = Resource, 3 = Exception, 4 = Security, etc.
    data_dirs = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    
    # DirectoryEntryExport (index 0)
    if len(data_dirs) > 0:
        directories['DirectoryEntryExport'] = 1 if data_dirs[0].VirtualAddress != 0 else 0
        directories['ImageDirectoryEntryExport'] = data_dirs[0].Size
    
    # DirectoryEntryImport (index 1)
    if len(data_dirs) > 1:
        directories['DirectoryEntryImport'] = 1 if data_dirs[1].VirtualAddress != 0 else 0
        directories['DirectoryEntryImportSize'] = data_dirs[1].Size
        directories['ImageDirectoryEntryImport'] = data_dirs[1].Size
    
    # DirectoryEntryResource (index 2)
    if len(data_dirs) > 2:
        directories['ImageDirectoryEntryResource'] = data_dirs[2].Size
    
    # DirectoryEntryException (index 3)
    if len(data_dirs) > 3:
        directories['ImageDirectoryEntryException'] = data_dirs[3].Size
    
    # DirectoryEntrySecurity (index 4)
    if len(data_dirs) > 4:
        directories['ImageDirectoryEntrySecurity'] = data_dirs[4].Size
    
    return directories


# ============================================================================
# MAIN FEATURE EXTRACTION
# ============================================================================

def extract_features(file_path: str, model_columns: List[str]) -> Optional[pd.DataFrame]:
    """
    Extract all 74 features from a PE file to match the model's schema.
    
    Args:
        file_path: Path to the PE file to analyze
        model_columns: List of column names expected by the model
        
    Returns:
        DataFrame with extracted features, or None on error
    """
    try:
        # Parse PE file
        pe = pefile.PE(file_path, fast_load=False)
        
        # Initialize feature dictionary
        data = {}
        
        # Extract all feature categories
        print("[*] Extracting DOS_HEADER features...")
        data.update(extract_dos_header(pe))
        
        print("[*] Extracting FILE_HEADER features...")
        data.update(extract_file_header(pe))
        
        print("[*] Extracting OPTIONAL_HEADER features...")
        data.update(extract_optional_header(pe))
        
        print("[*] Extracting section statistics...")
        data.update(extract_section_statistics(pe))
        
        print("[*] Extracting behavioral features...")
        data.update(extract_behavioral_features(pe))
        
        print("[*] Extracting directory entries...")
        data.update(extract_directory_entries(pe))
        
        # Close PE file
        pe.close()
        
        # Create DataFrame with exact column order from model
        features_df = pd.DataFrame([data], columns=model_columns)
        
        # Fill any missing values with 0
        features_df = features_df.fillna(0)
        
        # Verify feature count
        extracted_count = len([k for k in data.keys() if k in model_columns])
        print(f"[+] Extracted {extracted_count}/{len(model_columns)} features")
        
        if extracted_count < len(model_columns):
            missing = set(model_columns) - set(data.keys())
            print(f"[!] Warning: {len(missing)} features missing: {missing}")
        
        return features_df
        
    except pefile.PEFormatError as e:
        print(f"[!] Error: Not a valid PE file - {e}")
        return None
    except Exception as e:
        print(f"[!] Error parsing file: {e}")
        import traceback
        traceback.print_exc()
        return None


# ============================================================================
# PREDICTION EXPLANATION
# ============================================================================

def explain_prediction(model: object, columns: List[str], input_data: pd.DataFrame, top_n: int = 10) -> None:
    """
    Display the top N features that influenced the model's decision.
    
    Args:
        model: Trained model with feature_importances_ attribute
        columns: List of feature names
        input_data: DataFrame with extracted features
        top_n: Number of top features to display
    """
    # Check if model has feature importances
    if not hasattr(model, 'feature_importances_'):
        print("\n[!] Model does not support feature importance analysis")
        return
    
    # Get importance scores
    importances = model.feature_importances_
    
    # Sort by importance (descending)
    indices = np.argsort(importances)[::-1]
    
    print(f"\n" + "=" * 80)
    print(f"FEATURE IMPORTANCE ANALYSIS: Top {top_n} Features Driving Decision")
    print("=" * 80)
    print(f"{'Rank':<6} {'Feature Name':<35} {'File Value':<15} {'Importance':<12}")
    print("-" * 80)
    
    for rank, idx in enumerate(indices[:top_n], 1):
        feature_name = columns[idx]
        importance_score = importances[idx]
        file_value = input_data[feature_name].values[0]
        
        print(f"{rank:<6} {feature_name:<35} {file_value:<15.2f} {importance_score:<12.6f}")
    
    print("=" * 80)


# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """Main execution function."""
    
    # Check command line arguments
    if len(sys.argv) != 2:
        print("Usage: python pe-extractor-corrected.py <path_to_file>")
        print("\nExample:")
        print("  python pe-extractor-corrected.py suspicious.exe")
        sys.exit(1)
    
    target_file = sys.argv[1]
    
    # Validate file exists
    if not os.path.exists(target_file):
        print(f"[!] Error: File '{target_file}' not found.")
        sys.exit(1)
    
    # Load model and columns
    print("[*] Loading model resources...")
    model, columns = load_resources()
    
    # Extract features
    print(f"\n[*] Analyzing: {target_file}")
    print("=" * 80)
    input_data = extract_features(target_file, columns)
    
    if input_data is None:
        print("[!] Feature extraction failed. Cannot proceed with prediction.")
        sys.exit(1)
    
    # Make prediction
    print("\n[*] Running classification...")
    prediction = model.predict(input_data)[0]
    probabilities = model.predict_proba(input_data)[0]
    
    # Display results
    print("\n" + "=" * 80)
    print("CLASSIFICATION RESULT")
    print("=" * 80)
    
    if prediction == 1:
        print("[!] VERDICT: MALWARE DETECTED")
        print(f"    Malware Confidence: {probabilities[1]:.2%}")
        print(f"    Benign Confidence:  {probabilities[0]:.2%}")
    else:
        print("[+] VERDICT: CLEAN FILE")
        print(f"    Benign Confidence:  {probabilities[0]:.2%}")
        print(f"    Malware Confidence: {probabilities[1]:.2%}")
    
    print("=" * 80)
    
    # Explain prediction
    explain_prediction(model, columns, input_data, top_n=15)
    
    print("\n[*] Analysis complete.")


if __name__ == "__main__":
    main()
```

### It works

Let's take this thing for a spin in my Malware Analysis VM. This first sample is something I was messing around with revese engineering over Christmas called Santa Stealer. It was pretty confidently able to correclty classify as malware.  

![Image](/images/malware-analysis1.png?width=400px)  

### It still works!

Next up time for everyones favourite classic calc.exe. This again was correctly classified as benign!

![Image](/images/calc-tn.png?width=400px)  

### Annd it's useless!

Unsuprisingly a hastily trained Random Forest model falls short. PEStudio for anyone who doesn't spend too much time in their Malware Analysis VM is a fantastic tool for performing static analysis. 

To cut the model some slack PEStudio does inhibit some malicious looking qualities due to the way it pulls out static features from files. 

But as I probably said at the outset, the purpose of this whole endevour was exploration. Learning and finding out the shortcomings along the way, to then move onto bigger and better things which are more resiliant. 

![Image](/images/pestudio-fp.png?width=400px)  

There is obviously a lot more we could do, extract strings perform hash lookups and more to get higher quality of data to train this rudementary engine on. Also I could build a better dataset, producing data for all windows binaries on a typical system would likely improve performance as well as looking at other facets like file signatures. 

While these would be worthwhile if my aim was to create a more accurate detection tool, my aim is to dig deeper into ML so instead heres what I want to take this to in February!

### Whats next?

Next month I want to dig into some totally new topics to me as most of the above was re-familiarisation:

- SHAP analysis
- XG Boost
- Explore how I can build my own dataset from scatch

