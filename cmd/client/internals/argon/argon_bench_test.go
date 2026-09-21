package argon

import (
	"fmt"
	"testing"

	"github.com/awnumar/memguard"
)

func BenchmarkHashWithArgon(b *testing.B) {

	//5 types of string
	var examples = []string{
		"thisIsTheLongestPasswordInThisBenchmarkSetCreatedSpecificallyToObserveHowArgonBehavesWhenTheInputStringBecomesVeryLargeAndContainsLettersNumbersAndSymbols1234567890!@#$%^&*()_+-=[]{}|;:,.<>?",
	}

	for i := range 3 {
		b.Run(fmt.Sprintf("Level %d", i+1), func(b *testing.B) {
			password := memguard.NewEnclave([]byte(examples[0]))

			b.ResetTimer()   //time
			b.ReportAllocs() //ram

			for range b.N {
				hash, _, err := HashWithArgon(i+1, password)
				if err != nil {
					b.Fatal(err)
				}
				hash.Destroy()
			}
		})
	}
}
