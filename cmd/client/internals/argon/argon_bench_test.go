package argon

import (
	"P2Chat/cmd/client/internals/encryption"
	"fmt"
	"testing"
)

func BenchmarkHashWithArgon(b *testing.B) {
	
	//5 types of string
	var examples = []string{
		"thisIsTheLongestPasswordInThisBenchmarkSetCreatedSpecificallyToObserveHowArgonBehavesWhenTheInputStringBecomesVeryLargeAndContainsLettersNumbersAndSymbols1234567890!@#$%^&*()_+-=[]{}|;:,.<>?",
	}


	salt, _ := encryption.GenerateSalt(32)

	for i := range 3 {
		b.Run(fmt.Sprintf("Level %d",i+1),func(b *testing.B) {

			b.ResetTimer()		//time
			b.ReportAllocs()	//ram
			
			for range b.N {
				_ , err := HashWithArgon(i+1,encryption.Encaps(examples[0]),salt)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}