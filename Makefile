CC=cl
LINKER=link
RM=del /q

TARGET=logue.exe
OUTDIR=.\bin
OBJS=\
     $(OUTDIR)\dacl.obj\
     $(OUTDIR)\priv.obj\
     $(OUTDIR)\logue.obj\
     $(OUTDIR)\main.obj

CFLAGS=\
    /nologo\
    /Zi\
    /c\
    /Fo"$(OUTDIR)\\"\
    /Fd"$(OUTDIR)\\"\
    /D_UNICODE\
    /DUNICODE\
#    /O2\
    /W3\
    /EHsc

LFLAGS=\
    /NOLOGO\
    /DEBUG\
    /SUBSYSTEM:CONSOLE\
    /DYNAMICBASE "advapi32.lib" "user32.lib"

all: clean $(OUTDIR)\$(TARGET)

clean:
    -@if not exist $(OUTDIR) md $(OUTDIR)
    @$(RM) /Q $(OUTDIR)\* 2>nul

$(OUTDIR)\$(TARGET): $(OBJS)
    $(LINKER) $(LFLAGS) /PDB:"$(@R).pdb" /OUT:"$(OUTDIR)\$(TARGET)" $**

.cpp{$(OUTDIR)}.obj:
    $(CC) $(CFLAGS) $<
