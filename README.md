## LocalStranger

LocalStranger is a **Proof of Concept** project designed to demonstrate how dangerous a vulnerable kernel-mode driver actually is. 

`WinNotify.sys` (as I call it, `msft.sys`), is a very dangerous vulnerable driver exposing arbitrary kernel primitives due to a complete lack of caller validation. 
Unexpectedly, the driver is signed under the `Microsoft Windows Hardware Compatibility Publisher` partnership program and to this date, hasn't been added to the 
Microsoft Vulnerable Driver Blocklist. Apparently, as long as it isn't actively leveraged in the wild by a threat group, it basically isn't treated as anyone's problem.

Taking advantage of the driver, I was able to create a driver mapper to map unsigned kernel drivers into kernel space, and a program to elevate the user to NT-AUTHORITY.
Due to how dangerous the exposed primitives are, you can literally do anything you'd think of. The sky is the limit.

LocalStranger consists of one main core component, `lsapi` which implements wrappers around user-mode communications with the driver. From process R/W and memory allocations to KASLR bypass, physical
and virtual memory R/W.

The driver mapper, `lsmapper`, is written in C++ with a pretty modern syntax, because I felt like it.
Everything else's been written in C with a strong Microsoft formatting, because I also felt like doing.

The code has been shared without a license so don't ask me what that means, search it up.

## Screenshots
<img width="1690" height="928" alt="vmware_atMKc3A8I3" src="https://github.com/user-attachments/assets/c1965717-348c-4685-8e50-e4f682b111b2" />
<img width="1690" height="928" alt="vmware_SkiIZveojT" src="https://github.com/user-attachments/assets/bf5329eb-d7ca-4616-ba69-b97f308fd777" />
