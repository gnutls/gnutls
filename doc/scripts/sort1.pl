#!/usr/bin/perl

sub key_of_record {
  local($record) = @_;

  # Split record into lines:
  my @lines = split /\n/, $record;

  my ($i) = 1;
  my ($key) = $lines[$i]; 

  while( !($key =~ m/^\\label(.*)/) && ($i < 5)) { $i=$i+1; $key = $lines[$i]; }

  return $key;
}

$/="\n\n\n";          # Records are separated by blank lines.
@records = <>;  # Read in whole file, one record per array element.

@records = sort { key_of_record($a) cmp key_of_record($b) } @records;
print @records;
