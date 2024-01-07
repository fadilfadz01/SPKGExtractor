# SPKGExtractor
Dump SPKG update packages from Windows Phone 8 image.

This program is technically made to extract or dump the SPKG update packages from a Windows Phone 8 device that has access to the Mass Storage Mode, or from a mounted Windows Phone 8 image, and deploy it on another device that has an unlocked bootloader.

```
SPKGExtractor 1.0.0.0
Copyright (c) 2024 - Fadil Fadz

  -d, --drive     Required. A path to the source drive to dump the SPKG packages from.
                  Examples. D:\
                            D:\EFIESP

  -o, --output    Required. A path to the output folder to save the SPKG packages dump.
                  Examples. C:\Users\User\Desktop\Output
                            "C:\Users\User\Desktop\SPKG Dumps"

  -f, --filter    Optional. Dump only the given SPKG packages.
                  Examples. Microsoft.MainOS.Production
                            Microsoft.MainOS.Production;Microsoft.MobileCore.Prod.MainOS;...

  -s, --sign      (Default: false) Optional. Test sign the output SPKG packages.

  --help          Display this help screen.

  --version       Display version information.
```
