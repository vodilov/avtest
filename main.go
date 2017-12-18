package main

import (
	"bytes"
	"compress/gzip"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/mholt/archiver"
)

type Task struct {
	FileName string        // файл который будем проверять
	Dur      time.Duration // время проверки
}

type Stat struct {
	testName   string
	nFiles     int
	durTotal   time.Duration
	durAverage time.Duration
	durMin     time.Duration
	durMax     time.Duration
}

func printResult(v *Stat) {
	fmt.Println("\n====", v.testName, "====")
	fmt.Println("Total:", v.durTotal)
	fmt.Println("Average:", v.durAverage)
	fmt.Println("Min:", v.durMin)
	fmt.Println("Max:", v.durMax)
}

func main() {
	var (
		stat *Stat
	)

	runtime.GOMAXPROCS(200)

	filePtr := flag.String("f", "input.php", "Input file name")
	numbPtr := flag.Int("n", 20000, "Number of files you want to check")

	flag.Parse()

	fmt.Println("File:", *filePtr)
	fmt.Println("Number of files:", *numbPtr)

	files, targzipfiles := generateData(*filePtr, *numbPtr)
	//fmt.Println(files, targzipfiles)

	i360avService := "i360-clamd"
	i360avScanCmd := "/opt/alt/i360av/bin/clamdscan"

	i360agentService := "imunify360"
	i360agentCmd := "/opt/alt/python35/share/imunify360/scripts/modsec_scan.py"

	// i360-clamav

	restartService(i360avService)
	stat = CheckMultiFiles(i360avScanCmd, []string{files[0]}, 1)
	stat.testName = i360avService + ": Single input file 1 goroutine"
	printResult(stat)

	restartService(i360avService)
	stat = CheckMultiFiles(i360avScanCmd, []string{targzipfiles[0]}, 1)
	stat.testName = i360avService + ": Single input file (gziped) 1 goroutine"
	printResult(stat)

	restartService(i360avService)
	stat = CheckMultiFiles(i360avScanCmd, []string{"archive.zip"}, 1)
	stat.testName = i360avService + ": archive.zip 1 goroutine"
	printResult(stat)

	restartService(i360avService)
	stat = CheckMultiFiles(i360avScanCmd, files, 1)
	stat.testName = i360avService + ": PHP files 1 goroutine"
	printResult(stat)

	restartService(i360avService)
	stat = CheckMultiFiles(i360avScanCmd, files, 20)
	stat.testName = i360avService + ": PHP files 20 goroutines"
	printResult(stat)

	restartService(i360avService)
	stat = CheckMultiFiles(i360avScanCmd, files, 200)
	stat.testName = i360avService + ": PHP files 200 goroutines"
	printResult(stat)

	restartService(i360avService)
	stat = CheckMultiFiles(i360avScanCmd, targzipfiles, 1)
	stat.testName = i360avService + ": tar.gz files 1 goroutine"
	printResult(stat)

	restartService(i360avService)
	stat = CheckMultiFiles(i360avScanCmd, targzipfiles, 20)
	stat.testName = i360avService + ": tar.gz files 20 goroutines"
	printResult(stat)

	restartService(i360avService)
	stat = CheckMultiFiles(i360avScanCmd, targzipfiles, 200)
	stat.testName = i360avService + ": tar.gz files 200 goroutines"
	printResult(stat)

	// immunify360 modsec

	restartService(i360agentService)
	stat = CheckMultiFiles(i360agentCmd, []string{files[0]}, 1)
	stat.testName = i360agentService + ": Single input file 1 goroutine"
	printResult(stat)

	restartService(i360agentService)
	stat = CheckMultiFiles(i360agentCmd, []string{targzipfiles[0]}, 1)
	stat.testName = i360agentService + ": Single input file (gziped) 1 goroutine"
	printResult(stat)

	restartService(i360agentService)
	stat = CheckMultiFiles(i360agentCmd, []string{"archive.zip"}, 1)
	stat.testName = i360agentService + ": archive.zip 1 goroutine"
	printResult(stat)

	restartService(i360agentService)
	stat = CheckMultiFiles(i360agentCmd, files, 1)
	stat.testName = i360agentService + ": PHP files 1 goroutine"
	printResult(stat)

	restartService(i360agentService)
	stat = CheckMultiFiles(i360agentCmd, files, 20)
	stat.testName = i360agentService + ": PHP files 20 goroutines"
	printResult(stat)

	restartService(i360agentService)
	stat = CheckMultiFiles(i360agentCmd, files, 200)
	stat.testName = i360agentService + ": PHP files 200 goroutines"
	printResult(stat)

	restartService(i360agentService)
	stat = CheckMultiFiles(i360agentCmd, targzipfiles, 1)
	stat.testName = i360agentService + ": tar.gz files 1 goroutine"
	printResult(stat)

	restartService(i360agentService)
	stat = CheckMultiFiles(i360agentCmd, targzipfiles, 20)
	stat.testName = i360agentService + ": tar.gz files 20 goroutines"
	printResult(stat)

	restartService(i360agentService)
	stat = CheckMultiFiles(i360agentCmd, targzipfiles, 200)
	stat.testName = i360agentService + ": tar.gz files 200 goroutines"
	printResult(stat)

	clearData()

}

func checkTarget(e, filename string) {
	cmd := exec.Command(e, filename)
	cmdOutput := &bytes.Buffer{}
	cmd.Stdout = cmdOutput
	err := cmd.Run()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		fmt.Fprintln(os.Stderr, cmdOutput.String())
	}

}

func restartService(servname string) {
	fmt.Println("service", servname, "restart")

	cmd := exec.Command("service", servname, "restart")
	cmdOutput := &bytes.Buffer{}
	cmd.Stdout = cmdOutput
	err := cmd.Run()
	if err != nil {
		os.Stderr.WriteString(err.Error())
	}
	fmt.Print(string(cmdOutput.Bytes()))
	time.Sleep(5 * time.Second)
}

func generateData(filename string, count int) (files, targzipfiles []string) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}

	os.Mkdir("data", os.ModePerm)
	os.Mkdir("datagz", os.ModePerm)

	ext := filepath.Ext(filename)
	for i := 0; i < count; i++ {
		newContent := string(content) + "\n" + `// File ` + strconv.Itoa(i)

		fname := fmt.Sprintf(`data/file_%05d`+ext, i)
		files = append(files, fname)
		ioutil.WriteFile(fname, []byte(newContent), 0x777)

		fname = fmt.Sprintf(`datagz/file_%05d`+ext+`.gz`, i)
		targzipfiles = append(targzipfiles, fname)

		f, _ := os.Create(fname)
		w := gzip.NewWriter(f)
		w.Write([]byte(newContent))
		w.Close()
	}

	err = archiver.Zip.Make("archive.zip", []string{"data"})
	if err != nil {
		log.Fatal(err)
	}

	return
}

func clearData() {
	os.RemoveAll("data")
	os.RemoveAll("datagz")
	os.RemoveAll("archive.zip")
}

func CheckMultiFiles(e string, files []string, nGoroutines int) (stat *Stat) {
	nTasks := len(files)

	waitStart := sync.WaitGroup{}
	waitTasks := sync.WaitGroup{}

	waitStart.Add(1)

	fmt.Println("Start: ", time.Now())

	var sliceTasks []*Task

	for i := 0; i < nTasks; i++ {
		sliceTasks = append(sliceTasks, &Task{FileName: files[i]})
	}

	chQueue := make(chan *Task, nTasks)

	for _, e := range sliceTasks {
		chQueue <- e
	}

	close(chQueue)

	for i := 0; i < nGoroutines; i++ {
		waitTasks.Add(1)

		go func(q int) {
			waitStart.Wait()
			for currentTask := range chQueue { // Вычитываем таски из очереди

				startTime := time.Now()

				//time.Sleep(time.Second) // Работаем
				//fmt.Println(time.Now(), q, currentTask.FileName)
				checkTarget(e, currentTask.FileName)

				finishTime := time.Now()
				currentTask.Dur = finishTime.Sub(startTime)
			}

			waitTasks.Done()
		}(i)
	}

	waitStart.Done() // Делаю так что бы все 5 горутин проснулись
	t0Total := time.Now()
	waitTasks.Wait()
	durTotal := time.Now().Sub(t0Total)
	fmt.Println("durTotal: ", durTotal)

	var total, min, max time.Duration
	min = sliceTasks[0].Dur
	max = sliceTasks[0].Dur
	for _, v := range sliceTasks {
		total += v.Dur
		if min > v.Dur {
			min = v.Dur
		}
		if max < v.Dur {
			max = v.Dur
		}

	}
	average := time.Duration(float64(total) / float64(len(sliceTasks)))
	stat = &Stat{
		nFiles:     len(sliceTasks),
		durTotal:   durTotal,
		durAverage: average,
		durMin:     min,
		durMax:     max,
	}
	return
}
