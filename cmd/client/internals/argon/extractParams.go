package argon

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func ExtractParams()(ArgonParams,[]byte, error){

	var params ArgonParams 

	data, err := os.ReadFile("data/argonParams.dat")
	if err != nil {
		return ArgonParams{}, nil, fmt.Errorf("Extract Argon Params : error during reading file %w", err)
	}

	splits := strings.Split(string(data), "$")

	if !( len(splits) == 7 ) {
		return ArgonParams{}, nil, fmt.Errorf("Extract Argon Params : argonParams not correctly formatted.")
	}

	if !(splits[0] == "argon2id") {
		return ArgonParams{}, nil, fmt.Errorf("Extract Argon Params : error, the file is not an argon encoded string.")
	}

	var arr[5] int

	//convert params in the argonParams.dat into int type
	for i := 1 ; i <= 5 ; i++ {
		arr[i-1], err = strconv.Atoi(splits[i][2:])
		if err != nil {
			return ArgonParams{}, nil, fmt.Errorf("Extract Argon Params : error during Atoi() params, possible sintax NOT correct %w", err)
		}
	}

	//fill struct
	params.version = uint8(arr[0])
	params.memory = uint32(arr[1])
	params.time = uint32(arr[2])
	params.threads = uint8(arr[3])
	params.level = int(arr[4])
	params.len = 32


	
	err = checkParams(params.level, params)
	if err != nil {
		return ArgonParams{}, nil, fmt.Errorf("Extract Argon Params : error during extracting params from file, something went wrong... :( %w", err)
	}

	salt , err := base64.StdEncoding.DecodeString(splits[6])

	if err != nil {
		return ArgonParams{}, nil, fmt.Errorf("Extract Argon Params : error during extraction of hash , possible data corruption %w", err)
	}

	return params, salt, nil
}


func checkParams(level int, params ArgonParams) error {
	expected := argon2Params(level)

	if params.version != expected.version {
		return fmt.Errorf("argon params invalid: version mismatch, got %d want %d", params.version, expected.version)
	}

	if params.time != expected.time {
		return fmt.Errorf("argon params invalid: time mismatch, got %d want %d", params.time, expected.time)
	}

	if params.memory != expected.memory {
		return fmt.Errorf("argon params invalid: memory mismatch, got %d want %d", params.memory, expected.memory)
	}

	if params.threads != expected.threads {
		return fmt.Errorf("argon params invalid: threads mismatch, got %d want %d", params.threads, expected.threads)
	}

	if params.len != expected.len {
		return fmt.Errorf("argon params invalid: len mismatch, got %d want %d", params.len, expected.len)
	}

	return nil
}