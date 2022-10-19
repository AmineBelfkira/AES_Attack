# Ce Makefile permet de générer les executables
# - pour les tests f1main et f2main du repertoire tests
#-  pour le programme pccmain du repertoire src

# les fichiezrs executables sont situés sdnas le repertoire bin


#Les repertoires
#Pour les fichiers d'entete
INCDIR=./include
#Pour les fichiers executables
BINDIR=./bin
#Pour les fichiers binaires (.o)
OBJDIR=./obj
#Pour les fichiers de tests
TESTS=./tests
#Pour les fichiers sources .c
SRCDIR=./src

#Le nom du compilateur
CC=gcc

#Les options du compilateur : compilation (-c) et debug (-g). On peut ajouter -O3 pour optimiser quand le code est juste
#CFLAGS=-c -g -I$(INCDIR) 
CFLAGS=-std=c99 -c -g -pg -I$(INCDIR) 



#Les options de l'editeur de liens : -lm pour la bibliothèque mathématique. Voir les Makefile de TP pour ajouter la SDL si besoin
LDFLAGS= -lm


EXEDIR=$(BINDIR)/Exercice2_1 $(BINDIR)/Exercice1 $(BINDIR)/Exercice2_2 

 
OBJ=$(OBJDIR)/Exercice2_1.o $(OBJDIR)/Exercice1.o  $(OBJDIR)/Exercice2_2.o





all:  $(EXEDIR)
		

$(BINDIR)/Exercice1 : $(OBJDIR)/Exercice1.o $(OBJDIR)/aes-128_enc.o
	$(CC) -o $@ $^ $(LDFLAGS)

 
$(BINDIR)/Exercice2_1 :  $(OBJDIR)/Exercice2_1.o $(OBJDIR)/aes-128_enc.o
	$(CC) -o $@ $^ $(LDFLAGS)

$(BINDIR)/Exercice2_2 :  $(OBJDIR)/Exercice2_2.o $(OBJDIR)/aes-128_enc.o
	$(CC) -o $@ $^ $(LDFLAGS)	
	

$(OBJDIR)/%.o : $(TESTS)/%.c
	$(CC) $(CFLAGS) $^ -o $@

$(OBJDIR)/%.o : $(SRCDIR)/%.c
	$(CC) $(CFLAGS) $^ -o $@
	
	
clean: 
	rm -rf $(OBJDIR)/* $(BINDIR)/* $(EXEDIR) *.dSYM
	
	@echo "Make clean fait"

#Pour construire tous les executables
