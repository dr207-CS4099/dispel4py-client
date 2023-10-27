import sys
import csv
import json
import nltk
from nltk.corpus import wordnet
import re
import codecs
import operator
from dispel4py.workflow_graph import WorkflowGraph
from dispel4py.core import GenericPE
from dispel4py.base import IterativePE, ConsumerPE
import bisect
from os import path


# ROOT_DIR = "./"
ROOT_DIR = "./dispel4py/dispel4py/examples/article_sentiment_analysis/"

class ReadData(GenericPE):
    def __init__(self):
        GenericPE.__init__(self)
        self._add_output("output")
        self.count = 0

    def process(self, inputs):
        twitterData = inputs["input"]
        # print("Reading articles file %s" % ROOT_DIR + twitterData)
        article_file = open(path.join(ROOT_DIR, twitterData))

        for line in article_file:
            fields = line.split("\t")
            location = fields[3]
            text = fields[4]
            self.count += 1
            return_article = {"text": text, "location": location}
            # print("TEXT %s", text)
            self.write("output", return_article)

        print(f"Total articles found {self.count}")


class AFINNSentimeScore(IterativePE):
    def __init__(self, sentimentData):
        IterativePE.__init__(self)
        afinnfile = open(path.join(ROOT_DIR, sentimentData))
        self.sentiment = {}
        for line in afinnfile:
            # The file is tab-delimited. "\t" means "tab character"
            term, score = line.split("\t")
            self.sentiment[term] = float(score)  # Convert the score to an integer.
        self.method = "AFINN"

    def _process(self, data):
        article = data
        avg_score = 0
        count = 0
        article_word = nltk.word_tokenize(article["text"])
        sent_score = 0  # sentiment score della frase
        for word in article_word:
            word = word.rstrip('?:!.,;"!@')
            word = word.replace("\n", "")
            if not (word.encode("utf-8", "ignore") == ""):
                if word.encode("utf-8") in self.sentiment.keys():
                    sent_score = sent_score + float(self.sentiment[word])
                    count += 1
        if count != 0:
            avg_score = sent_score / count
        else:
            avg_score = sent_score

        return (article, avg_score, self.method)


class PrintAFINNScore(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)

    def _process(self, data):
        article, sent_score = data
        filename = path.join(ROOT_DIR, "Afiinscored.txt")
        with open(filename, "a+") as results:
            results.write(f"{article['text']} ------score: {sent_score}\n")


class FindState(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)

    def _process(self, data):
        article, sent_score, method = data

        state = self.find_state(article)

        if state:
            self.write("output", [article, sent_score, state, method])

    def find_state(self, article):
        return article["location"]


class HappyState(GenericPE):
    def __init__(self):
        GenericPE.__init__(self)
        self._add_input("input", grouping=[2, 3])
        self._add_output("output")
        self.mood = {}
        self.happiest = None, -5000

    def _process(self, inputs):
        article, sent_score, state, method = inputs["input"]

        if state not in self.mood:
            self.mood[state] = sent_score
        else:
            self.mood[state] += sent_score

        happiest_state, happiest_score = self.happiest

        if self.mood[state] > happiest_score:
            happiest_score = self.mood[state]
            self.happiest = state, happiest_score
            self.write("output", [state, happiest_score, method])


class GlobalHappyState(GenericPE):
    def __init__(self):
        GenericPE.__init__(self)
        self._add_input("input", grouping="global")
        self.state = None
        self.happiness = {}  # pair state, sentiment
        self.top_number = 3
        self.top_states = []
        self.top_scores = []
        self.total_articles = 0

    def _process(self, inputs):
        state, score, method = inputs["input"]
        self.total_articles += 1
        self.happiness[state] = score
        try:
            state_index = self.top_states.index(state)
            del self.top_states[state_index]
            del self.top_scores[state_index]
        except ValueError:
            pass
        index = bisect.bisect_left(self.top_scores, score)
        self.top_scores.insert(index, score)
        self.top_states.insert(index, state)
        if len(self.top_scores) > self.top_number:
            self.top_scores.pop(0)
            self.top_states.pop(0)
        self.score = self.top_scores[0]
        count = 0
        for score, state in zip(self.top_scores, self.top_states):
            print(
                f"METHOD:{method} - top:{count}----> state = {state}, score = {score}, total_articles = {self.total_articles}"
            )
            count += 1


class Tokenization_WD(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)

    def _process(self, data):
        article = data
        article_tagged = self.tag_article(article["text"])
        article_word_def = self.wordnet_definitions(article_tagged)
        return (article_word_def, article)

    def tag_article(self, article):
        sents = nltk.sent_tokenize(article)
        sentence = []
        for sent in sents:
            tokens = nltk.word_tokenize(sent)
            tag_tuples = nltk.pos_tag(tokens)
            for string, tag in tag_tuples:
                token = {"word": string, "pos": tag}
                sentence.append(token)
        return sentence

    def wordnet_definitions(self, sentence):
        wnl = nltk.WordNetLemmatizer()
        for token in sentence:
            word = token["word"]
            wn_pos = wordnet_pos_code(token["pos"])
            if self.is_punctuation(word):
                token["punct"] = True
            elif self.is_stopword(word):
                pass
            elif len(wordnet.synsets(word, wn_pos)) > 0:
                token["wn_lemma"] = wnl.lemmatize(word.lower())
                token["wn_pos"] = self.wordnet_pos_label(token["pos"])
                defs = [sense.definition() for sense in wordnet.synsets(word, wn_pos)]
                token["wn_def"] = "; \n".join(defs)
            else:
                pass
        return sentence

    def wordnet_pos_label(self, tag):
        if tag.startswith("NN"):
            return "Noun"
        elif tag.startswith("VB"):
            return "Verb"
        elif tag.startswith("JJ"):
            return "Adjective"
        elif tag.startswith("RB"):
            return "Adverb"
        else:
            return tag

    def is_stopword(self, string):
        return string.lower() in nltk.corpus.stopwords.words("english")

    def is_punctuation(self, string):
        for char in string:
            if char.isalpha() or char.isdigit():
                return False
        return True


class SentiWordNetScore(IterativePE):
    def __init__(self, sentimentData):
        IterativePE.__init__(self)
        self.filename = path.join(ROOT_DIR, sentimentData)
        self.db = {}
        self.sentiment = self.parse_src_file()
        self.threshold = 0.87

    def _process(self, data):
        article_word_def, article = data
        obj_score = 0  # object score
        pos_score = 0  # positive score
        neg_score = 0  # negative score
        pos_score_tre = 0
        neg_score_tre = 0
        count = 0
        count_tre = 0
        for word in article_word_def:
            if "punct" not in word:
                sense = self.word_sense_disambiguate(
                    word["word"], wordnet_pos_code(word["pos"]), article["text"]
                )
                if sense is not None:
                    sent = self.senti_synset(sense.name())
                    if sent is not None and sent.obj_score != 1:
                        obj_score = obj_score + float(sent.obj_score)
                        pos_score = pos_score + float(sent.pos_score)
                        neg_score = neg_score + float(sent.neg_score)
                        count = count + 1
                        if sent.obj_score < self.threshold:
                            pos_score_tre = pos_score_tre + float(sent.pos_score)
                            neg_score_tre = neg_score_tre + float(sent.neg_score)
                            count_tre = count_tre + 1

        return (article, pos_score_tre, neg_score_tre, count_tre)

    def parse_src_file(self):
        lines = codecs.open(self.filename, "r", "utf8").read().splitlines()
        lines = filter((lambda x: not re.search(r"^\s*#", x)), lines)
        for i, line in enumerate(lines):
            fields = re.split(r"\t+", line)
            try:
                pos, offset, pos_score, neg_score, synset_terms, gloss = fields
            except:
                sys.stderr.write(f"Line {i} formatted incorrectly: {line}\n")
            if pos and offset:
                offset = int(offset)
                self.db[(pos, offset)] = (float(pos_score), float(neg_score))

    def senti_synset(self, *vals):
        if tuple(vals) in self.db:
            pos_score, neg_score = self.db[tuple(vals)]
            pos, offset = vals
            synset = wordnet._synset_from_pos_and_offset(pos, offset)
            return SentiSynset(pos_score, neg_score, synset)
        else:
            synset = wordnet.synset(vals[0])
            pos = synset.pos()
            offset = synset.offset()
            if (pos, offset) in self.db:
                pos_score, neg_score = self.db[(pos, offset)]
                return SentiSynset(pos_score, neg_score, synset)
            else:
                return None

    def senti_synsets(self, string, pos=None):
        sentis = []
        synset_list = wordnet.synsets(string, pos)
        for synset in synset_list:
            sentis.append(self.senti_synset(synset.name))
        sentis = filter(lambda x: x, sentis)
        return sentis

    def all_senti_synsets(self):
        for key, fields in self.db.iteritems():
            pos, offset = key
            pos_score, neg_score = fields
            synset = wordnet._synset_from_pos_and_offset(pos, offset)
            yield SentiSynset(pos_score, neg_score, synset)

    def word_sense_disambiguate(self, word, wn_pos, article):
        senses = wordnet.synsets(word, wn_pos)
        if len(senses) > 0:
            cfd = nltk.ConditionalFreqDist(
                (sense, def_word)
                for sense in senses
                for def_word in sense.definition().split()
                if def_word in article
            )
            best_sense = senses[0]  # start with first sense
            for sense in senses:
                try:
                    if cfd[sense].max() > cfd[best_sense].max():
                        best_sense = sense
                except:
                    pass
            return best_sense
        else:
            return None


class SentiSynset:
    def __init__(self, pos_score, neg_score, synset):
        self.pos_score = pos_score
        self.neg_score = neg_score
        self.obj_score = 1.0 - (self.pos_score + self.neg_score)
        self.synset = synset

    def __str__(self):
        """Prints just the Pos/Neg scores for now."""
        return f"{self.synset.name()}\tPosScore: {self.pos_score}\t NegScore{self.neg_score}"

    def __repr__(self):
        return "Senti" + repr(self.synset)


class ComputeSentiWordNetScore(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
        self.method = "SWN3"

    def _process(self, data):
        article, pos_score_tre, neg_score_tre, count_tre = data
        if count_tre != 0:
            avg_pos_score_tre = pos_score_tre / count_tre
            avg_neg_score_tre = neg_score_tre / count_tre
            if avg_pos_score_tre > avg_neg_score_tre:
                sent_score = avg_pos_score_tre
            else:
                sent_score = (avg_neg_score_tre) * (-1)
            self.write("output", [article, sent_score, self.method])


# Translation from nltk to Wordnet (words tag) (code)
def wordnet_pos_code(tag):
    if tag.startswith("NN"):
        return wordnet.NOUN
    elif tag.startswith("VB"):
        return wordnet.VERB
    elif tag.startswith("JJ"):
        return wordnet.ADJ
    elif tag.startswith("RB"):
        return wordnet.ADV
    else:
        return ""


articles = ReadData()
articles.name = "read"
sentiment_afinn = AFINNSentimeScore("AFINN-111.txt")
findstate1 = FindState()
findstate2 = FindState()
happystate1 = HappyState()
happystate2 = HappyState()
happystate2.numprocesses = 3
findhappystate1 = GlobalHappyState()
findhappystate2 = GlobalHappyState()

preprocess_sentiword = Tokenization_WD()
sentiment_sentiword = SentiWordNetScore("SentiWordNet_3.0.0_20130122.txt")
sentiwordscore = ComputeSentiWordNetScore()

graph = WorkflowGraph()
graph.connect(articles, "output", sentiment_afinn, "input")
graph.connect(sentiment_afinn, "output", findstate1, "input")
graph.connect(findstate1, "output", happystate1, "input")
graph.connect(happystate1, "output", findhappystate1, "input")

graph.connect(articles, "output", preprocess_sentiword, "input")
graph.connect(preprocess_sentiword, "output", sentiment_sentiword, "input")
graph.connect(sentiment_sentiword, "output", sentiwordscore, "input")
graph.connect(sentiwordscore, "output", findstate2, "input")
graph.connect(findstate2, "output", happystate2, "input")
graph.connect(happystate2, "output", findhappystate2, "input")
