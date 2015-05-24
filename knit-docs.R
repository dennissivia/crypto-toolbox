library(knitr)

old_wd = getwd()

setwd('doc')
#knit('README.Rmd')
setwd("matasano")
knit('README.Rmd')

setwd(old_wd)
