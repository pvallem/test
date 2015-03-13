import logging
import argparse
import glob
import os, sys
import threading
import time
import numpy as np
import math


class CollaberiveFilter(object):
    """ Implements the collaberive filtering on Netflix data."""
    def __init__(self, training_file, test_file, num_of_movies, num_of_users):
        """ Declares and initializes the required class variables."""
        self.training_file = training_file
        self.test_file = test_file
        self.users = {}
        self.movies = {}
        self.movies_ulist = {}
        self.users_mlist = {}
        self.user_means = None
        self.movie_means = None
        self.num_of_movies = num_of_movies
        self.num_of_users = num_of_users
        self.test_ratings = None
        self.train_ratings = np.zeros((num_of_movies, num_of_users), float)
        self.weights = {}
        self.avg_ratings_user = np.zeros((1, num_of_users), float)

    def set_given_ratings(self):
        """ Sets the given ratings from the training file."""
        ratings = np.genfromtxt(self.training_file, delimiter=',')
        i = 0
        j = 0
        for rating in ratings:
            if int(rating[0]) in self.movies:
                mov_id = self.movies[int(rating[0])]
            else:
                mov_id = i
                self.movies[int(rating[0])] = i
                i += 1

            if int(rating[1]) in self.users:
                user_id = self.users[int(rating[1])]
            else:
                user_id = j
                self.users[int(rating[1])] = j
                j += 1
            self.train_ratings[mov_id][user_id] = rating[2]
            if mov_id in self.movies_ulist:
                self.movies_ulist[mov_id].append(user_id)
            else:
                self.movies_ulist[mov_id] = [user_id]

            if user_id in self.users_mlist:
                self.users_mlist[user_id].append(mov_id)
            else:
                self.users_mlist[user_id] = [mov_id]

    def get_means(self):
        """ Returns the means of users and movies."""
        self.train_ratings[np.where(self.train_ratings == 0)] = np.nan

        self.user_means = [ round(x, 3) for x in np.nanmean(self.train_ratings, axis=0) ]
        self.movie_means = [ round(x, 3) for x in np.nanmean(self.train_ratings, axis=1) ]

    def get_user_diff(self, movieid, userid):
        if str(self.train_ratings[movieid][userid]) == "nan" and \
                str(self.user_means[userid]) == "nan":
            diff = 0
        elif str(self.train_ratings[movieid][userid]) == "nan":
            diff = 0 - self.user_means[userid]
        elif str(self.user_means[userid]) == "nan":
            diff = self.train_ratings[movieid][userid]
        else:
            diff = self.train_ratings[movieid][userid] - \
                self.user_means[userid]
        return diff
        
    def get_weight(self, user1, user2):
        """ Returns the correlation weight between user1 and user2."""
        if user1 > user2:
            a = user1
            b = user2
        else:
            a = user2
            b = user1
        if (a, b) in self.weights:
            return self.weights[(a, b)]

        num = 0
        den1 = 0
        den2 = 0
        for j in set(self.users_mlist[user1]).intersection(self.users_mlist[user2]):
            user1_diff = self.get_user_diff(j, user1)
            user2_diff = self.get_user_diff(j, user2)
            num += user1_diff*user2_diff
            den1 += user1_diff*user1_diff
            den2 += user2_diff*user2_diff
            
        den = math.sqrt(den1*den2)
        if str(den) == "nan":
            print str(den) + " is denominator."
        if den != 0:
            weight = round((num*1.0)/(den*1.0), 3)
        else:
            weight = 0
        
        if weight is np.nan:
            weight = 0
            print str(weight) + " is weight for users " +  str(user1) + " " + str(user2) 
        self.weights[(a, b)] = weight
        return weight

    def set_test_ratings(self):
        """ sets the test file ratings."""
        self.test_ratings = np.genfromtxt(self.test_file, delimiter=',')

    def predict_rating(self, userid, movieid):
        """ Returns the predicted rating of the movie by user."""
        sum = 0
        weightSum = 0
        
        for i in set(self.movies_ulist[movieid]):
            if i == userid:
                continue
            weight = self.get_weight(userid, i)
            weightSum += weight
            sum += weight*(self.get_user_diff(movieid, i))
            if str(sum) == "nan":
                print "sum is " + str(sum) + " user id is " + str(i)
                break


        # print str(sum) + " is sum."
        if weightSum == 0:
            weightSum = 1
        sum = round((1.0*sum/weightSum), 3)
        # print str(sum) + " is sum."
        rating = self.user_means[userid] + sum
        if abs(rating) > 5:
            return rating % 5
        return rating
        
    def claculate_error(self, start, end, errors):
        """ This method caluclates the errors in test data from start 
        to end position and stores the errors in the error, error^2 list."""
        i = start
        MAE = 0
        RMSE = 0
        while i <= end:
            movieid = self.movies[int(self.test_ratings[i][0])]
            userid = self.users[int(self.test_ratings[i][1])]
            expected_rating = self.predict_rating(userid, movieid)
            #print str(expected_rating) + " is predicted rating for " + str(self.test_ratings[i][0]) +\
            #    " movie by user " + str(int(self.test_ratings[i][1])) + " where actual rating is " +\
            #    str(int(self.test_ratings[i][2]))
            error = abs(int(self.test_ratings[i][2]) - expected_rating)
            MAE = MAE + error
            RMSE = RMSE + error * error
            i += 1
            if i % 1000 == 0:
                print "{0} records processing finished, MAE: {1}, RMSE: {2}".format(i, MAE, RMSE)
        errors.append((MAE, RMSE))

    def calculate_errors(self):
        """ Calculates the mean absolute error and root mean square error."""
        self.set_test_ratings()
        MAE = 0
        RMSE = 0
        start = 0
        error_list = []
        thread_list = []
        no_threads = 20
        total_tests = len(self.test_ratings)
        sub_tests = total_tests/no_threads
        end = sub_tests - 1
        while start < total_tests:
            if end >= total_tests:
                end = total_tests - 1
                n = no_threads
            error = []
            error_list.append(error)
            t = threading.Thread(target=self.claculate_error, args=(start, end, error))
            t.run()
            thread_list.append(t)
            start += sub_tests
            end += sub_tests
            
        # wait untiul all the therads are Finished.
        for t in thread_list:
            try:
                t.join()
            except:
                continue

        #error = []
        #error_list.append(error)
        #self.claculate_error(0, total_tests - 1, error)
            
        for error in error_list:
            MAE += error[0][0]
            RMSE += error[0][1]
        MAE = MAE/total_tests
        RMSE = math.sqrt(RMSE/total_tests)
        return MAE, RMSE

def main():
    """The control and execute block of the program."""
    parser = argparse.ArgumentParser(prog='collabartive_filtering.py')
    parser.add_argument('-tr', nargs=1, required=True,
                        help="training set path.")
    parser.add_argument('-te',  nargs=1, required=True,
                        help="test set path.")
    parser.add_argument('-nu', nargs=1, required=False,
                        help="number of users.")
    parser.add_argument('-nm',  nargs=1, required=False,
                        help="number of movies.")
    args = parser.parse_args()
    
    try:
        users = int(args.nu[0])
    except:
        users = 28978

    try:
        movies = int(args.nm[0])
    except:
        movies = 1821

    cF = CollaberiveFilter(args.tr[0], args.te[0], movies, users)
    cF.set_given_ratings()
    cF.get_means()
    print cF.train_ratings[cF.movies[8]][cF.users[1818178]]
    print cF.user_means[cF.users[1818178]]
    errors = cF.calculate_errors()
    print "Mean Absolute Error = " + str(errors[0])
    print "Root Mean Square Error = " + str(errors[1])


if __name__ == "__main__":
    """Start of program."""
    main()


   
        
